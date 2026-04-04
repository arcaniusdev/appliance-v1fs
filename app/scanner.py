import json
import logging
import os
import random
import signal
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlencode

import boto3
import grpc
import amaas.grpc

logger = logging.getLogger("scanner")
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    level=os.environ.get("LOG_LEVEL", "INFO"),
)

# Module-level state — shared across worker threads (read-heavy, write-rare)
_channels = None
_channels_built_at = 0.0  # monotonic timestamp of last channel build
_channels_lock = threading.Lock()  # Protects channel rebuild
_s3_client = None
_logs_client = None
_audit_stream_created = False

SCANNER_ACCOUNT_ID = os.environ.get("SCANNER_ACCOUNT_ID", "")
QUARANTINE_BUCKET = os.environ.get("QUARANTINE_BUCKET", "")

# Channel refresh interval — reconnect periodically to rebalance across NLB targets
CHANNEL_REFRESH_SECONDS = 60

# Shutdown coordination
_shutdown_event = threading.Event()


def _get_s3():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3")
    return _s3_client


def _get_logs():
    global _logs_client
    if _logs_client is None:
        _logs_client = boto3.client("logs")
    return _logs_client



def _build_channels():
    global _channels, _channels_built_at

    with _channels_lock:
        # Double-check after acquiring lock
        if _channels is not None and (time.monotonic() - _channels_built_at <= CHANNEL_REFRESH_SECONDS):
            return

        endpoint = os.environ.get("SCANNER_ENDPOINT", "")
        if not endpoint:
            raise RuntimeError("SCANNER_ENDPOINT not set")
        addr = f"{endpoint}:443"

        sm = boto3.client("secretsmanager")
        api_key = sm.get_secret_value(
            SecretId=os.environ["V1FS_API_KEY_SECRET_ARN"]
        )["SecretString"]
        ca_cert = sm.get_secret_value(
            SecretId=os.environ["SG_CA_CERT_SECRET_ARN"]
        )["SecretString"].encode("utf-8")

        call_creds = grpc.metadata_call_credentials(
            lambda context, callback: callback(
                [("authorization", f"Bearer {api_key}")], None
            )
        )
        channel_creds = grpc.ssl_channel_credentials(root_certificates=ca_cert)
        composite = grpc.composite_channel_credentials(channel_creds, call_creds)

        tls_override = os.environ.get("SG_TLS_OVERRIDE", "sg.sgi.xdr.trendmicro.com")
        max_file_bytes = int(os.environ.get("MAX_FILE_SIZE_MB", "500")) * 1024 * 1024
        options = [
            ("grpc.ssl_target_name_override", tls_override),
            ("grpc.max_send_message_length", max_file_bytes),
            ("grpc.max_receive_message_length", max_file_bytes),
            ("grpc.keepalive_time_ms", 30_000),
            ("grpc.keepalive_timeout_ms", 10_000),
            ("grpc.keepalive_permit_without_calls", 1),
            ("grpc.use_local_subchannel_pool", 1),
        ]

        num_channels = int(os.environ.get("GRPC_CHANNELS", "8"))
        channels = []
        for _ in range(num_channels):
            channels.append(grpc.secure_channel(addr, composite, options=options))
        logger.info("Created %d gRPC channel(s) to %s", num_channels, addr)

        _channels = channels
        _channels_built_at = time.monotonic()


def _get_channel():
    """Return a gRPC channel. NLB distributes each channel to a different SG."""
    if _channels is None or (time.monotonic() - _channels_built_at > CHANNEL_REFRESH_SECONDS):
        _build_channels()
    return random.choice(_channels)



# -- Core Scan Logic ----------------------------------------------------------

SOURCE_BUCKET = os.environ.get("SOURCE_BUCKET", "")


def _process_file(s3, scan_bucket, key, size, pml, feedback, audit_log_group):
    logger.info("Processing s3://%s/%s (%d bytes)", scan_bucket, key, size)
    sg_addr = os.environ.get("SCANNER_ENDPOINT", "unknown")

    try:
        resp = s3.get_object(Bucket=scan_bucket, Key=key)
        file_bytes = resp["Body"].read()
    except s3.exceptions.NoSuchKey:
        logger.warning("s3://%s/%s gone, skipping", scan_bucket, key)
        return

    for attempt in range(3):
        channel = _get_channel()
        scan_start = time.monotonic()
        try:
            result_json = amaas.grpc.scan_buffer(
                channel, file_bytes, os.path.basename(key),
                tags=["S3-Scan"], pml=pml, feedback=feedback,
            )
            break
        except Exception as exc:
            if "RESOURCE_EXHAUSTED" in str(type(exc).__name__) or "Cannot allocate resource" in str(exc):
                if attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
                    continue
            raise
    scan_ms = int((time.monotonic() - scan_start) * 1000)
    result = json.loads(result_json)
    is_malicious = result.get("scanResult", 0) > 0
    scan_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if is_malicious:
        malware_names = [m.get("malwareName", "") for m in result.get("foundMalwares", [])]
        logger.warning(
            "MALICIOUS: s3://%s/%s malware=%s scan=%dms sg=%s",
            scan_bucket, key, malware_names, scan_ms, sg_addr,
        )
        # Tag the source object to block access via bucket policy
        s3.put_object_tagging(
            Bucket=SOURCE_BUCKET, Key=key,
            Tagging={"TagSet": [
                {"Key": "ScanResult", "Value": "Malware"},
                {"Key": "ScanTimestamp", "Value": scan_ts},
            ]},
        )
        # Copy to quarantine bucket with metadata
        quarantine_key = f"{SOURCE_BUCKET}/{key}"
        tags = urlencode({
            "ScanResult": "Malware",
            "ScanTimestamp": scan_ts,
            "SourceBucket": SOURCE_BUCKET,
        })
        s3.put_object(
            Bucket=QUARANTINE_BUCKET, Key=quarantine_key,
            Body=file_bytes, Tagging=tags,
        )
        verdict = "malicious"
    else:
        logger.info("CLEAN: s3://%s/%s scan=%dms sg=%s",
                     scan_bucket, key, scan_ms, sg_addr)
        verdict = "clean"

    # Delete the staging copy — scan is done, source bucket has the original
    s3.delete_object(Bucket=scan_bucket, Key=key)

    _audit(audit_log_group, scan_bucket, key, size, verdict, result, scan_ms, sg_addr,
           SCANNER_ACCOUNT_ID)
    del file_bytes


_audit_lock = threading.Lock()


def _audit(log_group, bucket, key, size, verdict, result, scan_ms, sg_addr, source_account):
    global _audit_stream_created
    if not log_group:
        return
    stream = f"scanner-{socket.gethostname()}"
    entry = {
        "timestamp": time.time(),
        "file": key,
        "bucket": bucket,
        "sourceBucket": SOURCE_BUCKET,
        "size": size,
        "verdict": verdict,
        "scanResult": result.get("scanResult", -1),
        "sha256": result.get("fileSHA256", ""),
        "malware": [m.get("malwareName", "") for m in result.get("foundMalwares", [])],
        "scanId": result.get("scanId", ""),
        "scanDurationMs": scan_ms,
        "serviceGateway": sg_addr,
    }
    log_event = [{"timestamp": int(time.time() * 1000), "message": json.dumps(entry)}]

    try:
        logs = _get_logs()
        with _audit_lock:
            if not _audit_stream_created:
                try:
                    logs.create_log_stream(logGroupName=log_group, logStreamName=stream)
                except Exception:
                    pass
                _audit_stream_created = True
        logs.put_log_events(logGroupName=log_group, logStreamName=stream, logEvents=log_event)
    except Exception:
        logger.warning("Audit write failed", exc_info=True)


# -- SQS Message Processing --------------------------------------------------

def _heartbeat(sqs, queue_url, receipt_handle, visibility_timeout, stop_event):
    """Extend SQS message visibility periodically until stop_event is set."""
    interval = max(visibility_timeout - 60, 30)
    while not stop_event.wait(timeout=interval):
        try:
            sqs.change_message_visibility(
                QueueUrl=queue_url,
                ReceiptHandle=receipt_handle,
                VisibilityTimeout=visibility_timeout,
            )
        except Exception:
            logger.warning("Failed to extend visibility", exc_info=True)
            return  # Stop heartbeat — message may become visible to other workers


def _process_message(sqs, queue_url, message, visibility_timeout):
    """Process a single SQS message: parse, scan, delete or let retry."""
    message_id = message.get("MessageId", "unknown")
    receipt_handle = message["ReceiptHandle"]

    # Start heartbeat thread to keep message invisible during long scans
    heartbeat_stop = threading.Event()
    heartbeat_thread = threading.Thread(
        target=_heartbeat,
        args=(sqs, queue_url, receipt_handle, visibility_timeout, heartbeat_stop),
        daemon=True,
    )
    heartbeat_thread.start()

    s3 = _get_s3()
    pml = os.environ.get("PML_ENABLED", "true").lower() == "true"
    feedback = os.environ.get("FEEDBACK_ENABLED", "true").lower() == "true"
    audit_log_group = os.environ.get("AUDIT_LOG_GROUP", "")

    try:
        body = json.loads(message["Body"])
        # EventBridge event format: detail.bucket.name, detail.object.key
        detail = body.get("detail", {})
        scan_bucket = detail.get("bucket", {}).get("name")
        key = detail.get("object", {}).get("key")
        size = detail.get("object", {}).get("size", 0)

        if not scan_bucket or not key:
            logger.error("Missing bucket/key in event: %s", json.dumps(body)[:500])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
            return

        _process_file(s3, scan_bucket, key, size, pml, feedback, audit_log_group)
        # Success — delete message from queue
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)

    except Exception:
        logger.exception("Failed processing SQS message %s", message_id)
        # Let visibility expire for automatic retry (SQS redrive to DLQ after 5 failures)
        # Shorten visibility for faster retry
        try:
            sqs.change_message_visibility(
                QueueUrl=queue_url,
                ReceiptHandle=receipt_handle,
                VisibilityTimeout=30,
            )
        except Exception:
            pass
    finally:
        heartbeat_stop.set()
        heartbeat_thread.join(timeout=5)


# -- ASG Lifecycle -----------------------------------------------------------

def _complete_lifecycle_action():
    """Signal ASG that this instance is ready to terminate."""
    try:
        token_url = "http://169.254.169.254/latest/api/token"
        import urllib.request
        req = urllib.request.Request(token_url, method="PUT",
                                     headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
        token = urllib.request.urlopen(req, timeout=2).read().decode()
        meta_headers = {"X-aws-ec2-metadata-token": token}
        instance_id = urllib.request.urlopen(
            urllib.request.Request("http://169.254.169.254/latest/meta-data/instance-id",
                                   headers=meta_headers), timeout=2).read().decode()
    except Exception:
        logger.info("Not running on EC2 or IMDS unavailable — skipping lifecycle completion")
        return

    asg_name = os.environ.get("ASG_NAME")
    if not asg_name:
        logger.info("ASG_NAME not set — skipping lifecycle completion")
        return

    try:
        autoscaling = boto3.client("autoscaling")
        autoscaling.complete_lifecycle_action(
            LifecycleHookName="WorkerTerminationHook",
            AutoScalingGroupName=asg_name,
            InstanceId=instance_id,
            LifecycleActionResult="CONTINUE",
        )
        logger.info("Lifecycle action completed for %s", instance_id)
    except Exception:
        logger.warning("Failed to complete lifecycle action — ASG will time out and CONTINUE",
                       exc_info=True)


# -- Main Entry Point --------------------------------------------------------

def main():
    """Long-running SQS poller with concurrent scan workers."""
    sqs = boto3.client("sqs")
    queue_url = os.environ["SQS_QUEUE_URL"]
    max_workers = int(os.environ.get("MAX_CONCURRENT_SCANS", "50"))
    visibility_timeout = int(os.environ.get("SQS_VISIBILITY_TIMEOUT", "300"))
    consecutive_errors = 0

    logger.info(
        "Scanner worker starting — queue=%s concurrency=%d hostname=%s",
        queue_url, max_workers, socket.gethostname(),
    )

    # Pre-build gRPC channels before accepting work
    _build_channels()
    logger.info("gRPC channels ready")

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        in_flight = set()

        while not _shutdown_event.is_set():
            # Clean up completed futures
            done = {f for f in in_flight if f.done()}
            in_flight -= done
            # Log any exceptions from completed futures
            for f in done:
                exc = f.exception()
                if exc:
                    logger.error("Worker thread raised: %s", exc)

            # Backpressure: pause polling when workers are saturated
            if len(in_flight) >= max_workers:
                time.sleep(0.1)
                continue

            # Long-poll SQS (up to 10 messages, 20s wait)
            try:
                resp = sqs.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=20,
                    AttributeNames=["All"],
                )
                consecutive_errors = 0
            except Exception:
                consecutive_errors += 1
                delay = min(2 ** consecutive_errors, 60) + random.uniform(0, 1)
                logger.exception("SQS receive_message error, retrying in %.1fs", delay)
                time.sleep(delay)
                continue

            for msg in resp.get("Messages", []):
                future = pool.submit(
                    _process_message, sqs, queue_url, msg, visibility_timeout,
                )
                in_flight.add(future)

        # Graceful shutdown: wait for in-flight scans to finish
        logger.info("Shutting down — waiting for %d in-flight scans", len(in_flight))
        for f in as_completed(in_flight, timeout=300):
            exc = f.exception()
            if exc:
                logger.error("Worker thread raised during shutdown: %s", exc)

    _complete_lifecycle_action()
    logger.info("Shutdown complete")


def _handle_signal(signum, frame):
    sig_name = signal.Signals(signum).name
    logger.info("Received %s — initiating graceful shutdown", sig_name)
    _shutdown_event.set()


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    main()

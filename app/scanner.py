import asyncio
import json
import logging
import os
import random
import signal
import socket
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

import boto3
import amaas.grpc.aio
from aiobotocore.session import AioSession

logger = logging.getLogger("scanner")
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    level=os.environ.get("LOG_LEVEL", "INFO"),
)

SCANNER_ACCOUNT_ID = os.environ.get("SCANNER_ACCOUNT_ID", "")
SOURCE_BUCKET = os.environ.get("SOURCE_BUCKET", "")
QUARANTINE_BUCKET = os.environ.get("QUARANTINE_BUCKET", "")


# ── Scan Handle ──────────────────────────────────────────────────────

def _build_scan_handle():
    """Create a single async scan handle pointing at the ALB."""
    endpoint = os.environ.get("SCANNER_ENDPOINT", "")
    if not endpoint:
        raise RuntimeError("SCANNER_ENDPOINT not set")

    sm = boto3.client("secretsmanager")
    api_key = sm.get_secret_value(
        SecretId=os.environ["V1FS_API_KEY_SECRET_ARN"]
    )["SecretString"]
    ca_cert_pem = sm.get_secret_value(
        SecretId=os.environ["SG_CA_CERT_SECRET_ARN"]
    )["SecretString"]

    # Write CA cert to temp file for the SDK
    cert_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".pem", delete=False
    )
    cert_file.write(ca_cert_pem)
    cert_file.close()

    # init() is synchronous — do NOT await
    handle = amaas.grpc.aio.init(endpoint, api_key, True, ca_cert=cert_file.name)
    logger.info("Async scan handle created for %s", endpoint)
    return handle


# ── Core Scan Logic ──────────────────────────────────────────────────

async def _process_file(s3, scan_bucket, key, size, pml,
                        audit_log_group, logs, scan_handle):
    logger.info("Processing s3://%s/%s (%d bytes)", scan_bucket, key, size)
    sg_addr = os.environ.get("SCANNER_ENDPOINT", "unknown")

    try:
        resp = await s3.get_object(Bucket=scan_bucket, Key=key)
        async with resp["Body"] as stream:
            file_bytes = await stream.read()
    except Exception as exc:
        if "NoSuchKey" in str(type(exc).__name__) or "NoSuchKey" in str(exc):
            logger.warning("s3://%s/%s gone, skipping", scan_bucket, key)
            return
        raise

    for attempt in range(3):
        scan_start = time.monotonic()
        try:
            result_json = await amaas.grpc.aio.scan_buffer(
                scan_handle, file_bytes, os.path.basename(key),
                pml=pml, tags=["S3-Scan"],
            )
            break
        except Exception:
            if attempt < 2:
                await asyncio.sleep(0.5 * (attempt + 1))
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
        await s3.put_object_tagging(
            Bucket=SOURCE_BUCKET, Key=key,
            Tagging={"TagSet": [
                {"Key": "ScanResult", "Value": "Malware"},
                {"Key": "ScanTimestamp", "Value": scan_ts},
            ]},
        )
        quarantine_key = f"{SOURCE_BUCKET}/{key}"
        tags = urlencode({
            "ScanResult": "Malware",
            "ScanTimestamp": scan_ts,
            "SourceBucket": SOURCE_BUCKET,
        })
        await s3.put_object(
            Bucket=QUARANTINE_BUCKET, Key=quarantine_key,
            Body=file_bytes, Tagging=tags,
        )
        verdict = "malicious"
    else:
        logger.info("CLEAN: s3://%s/%s scan=%dms sg=%s",
                     scan_bucket, key, scan_ms, sg_addr)
        verdict = "clean"

    await s3.delete_object(Bucket=scan_bucket, Key=key)

    await _audit(logs, audit_log_group, scan_bucket, key, size, verdict,
                 result, scan_ms, sg_addr, SCANNER_ACCOUNT_ID)
    del file_bytes


# ── Audit Trail ──────────────────────────────────────────────────────

_audit_stream_created = False
_audit_lock = asyncio.Lock()


async def _audit(logs, log_group, bucket, key, size, verdict, result,
                 scan_ms, sg_addr, source_account):
    global _audit_stream_created
    if not log_group or not logs:
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
        async with _audit_lock:
            if not _audit_stream_created:
                try:
                    await logs.create_log_stream(logGroupName=log_group, logStreamName=stream)
                except Exception:
                    pass
                _audit_stream_created = True
        await logs.put_log_events(logGroupName=log_group, logStreamName=stream, logEvents=log_event)
    except Exception:
        logger.warning("Audit write failed", exc_info=True)


# ── SQS Message Processing ──────────────────────────────────────────

async def _process_message(sqs, s3, logs, queue_url, message, scan_handle, visibility_timeout):
    message_id = message.get("MessageId", "unknown")
    receipt_handle = message["ReceiptHandle"]

    async def heartbeat():
        interval = max(visibility_timeout - 60, 30)
        while True:
            await asyncio.sleep(interval)
            try:
                await sqs.change_message_visibility(
                    QueueUrl=queue_url,
                    ReceiptHandle=receipt_handle,
                    VisibilityTimeout=visibility_timeout,
                )
            except Exception:
                logger.warning("Failed to extend visibility", exc_info=True)
                return

    heartbeat_task = asyncio.create_task(heartbeat())
    pml = os.environ.get("PML_ENABLED", "true").lower() == "true"
    audit_log_group = os.environ.get("AUDIT_LOG_GROUP", "")

    try:
        body = json.loads(message["Body"])
        detail = body.get("detail", {})
        scan_bucket = detail.get("bucket", {}).get("name")
        key = detail.get("object", {}).get("key")
        size = detail.get("object", {}).get("size", 0)

        if not scan_bucket or not key:
            logger.error("Missing bucket/key in event: %s", json.dumps(body)[:500])
            await sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
            return

        await _process_file(s3, scan_bucket, key, size, pml,
                            audit_log_group, logs, scan_handle)
        await sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)

    except Exception:
        logger.exception("Failed processing SQS message %s", message_id)
        try:
            await sqs.change_message_visibility(
                QueueUrl=queue_url,
                ReceiptHandle=receipt_handle,
                VisibilityTimeout=30,
            )
        except Exception:
            pass
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


# ── ASG Lifecycle ────────────────────────────────────────────────────

def _complete_lifecycle_action():
    try:
        import urllib.request
        req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token", method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
        token = urllib.request.urlopen(req, timeout=2).read().decode()
        meta_headers = {"X-aws-ec2-metadata-token": token}
        instance_id = urllib.request.urlopen(
            urllib.request.Request("http://169.254.169.254/latest/meta-data/instance-id",
                                   headers=meta_headers), timeout=2).read().decode()
    except Exception:
        return

    asg_name = os.environ.get("ASG_NAME")
    if not asg_name:
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
        logger.warning("Failed to complete lifecycle action", exc_info=True)


# ── Main ─────────────────────────────────────────────────────────────

async def async_main():
    shutdown_event = asyncio.Event()
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGTERM, shutdown_event.set)
    loop.add_signal_handler(signal.SIGINT, shutdown_event.set)

    queue_url = os.environ["SQS_QUEUE_URL"]
    max_concurrent = int(os.environ.get("MAX_CONCURRENT_SCANS", "50"))
    visibility_timeout = int(os.environ.get("SQS_VISIBILITY_TIMEOUT", "300"))
    semaphore = asyncio.Semaphore(max_concurrent)
    consecutive_errors = 0

    scan_handle = _build_scan_handle()

    logger.info(
        "Scanner worker starting — queue=%s concurrency=%d hostname=%s",
        queue_url, max_concurrent, socket.gethostname(),
    )

    session = AioSession()
    async with session.create_client("sqs") as sqs, \
               session.create_client("s3") as s3, \
               session.create_client("logs") as logs:

        in_flight: set[asyncio.Task] = set()

        async def guarded_process(message):
            async with semaphore:
                await _process_message(sqs, s3, logs, queue_url, message,
                                       scan_handle, visibility_timeout)

        while not shutdown_event.is_set():
            if len(in_flight) >= max_concurrent * 2:
                await asyncio.sleep(0.1)
                done = {t for t in in_flight if t.done()}
                in_flight -= done
                for t in done:
                    if t.exception():
                        logger.error("Task raised: %s", t.exception())
                continue

            try:
                resp = await sqs.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=20,
                    AttributeNames=["All"],
                )
                consecutive_errors = 0
            except Exception:
                consecutive_errors += 1
                delay = min(2 ** consecutive_errors, 60) + random.uniform(0, 1)
                logger.exception("SQS error, retrying in %.1fs", delay)
                await asyncio.sleep(delay)
                continue

            for msg in resp.get("Messages", []):
                task = asyncio.create_task(guarded_process(msg))
                in_flight.add(task)
                task.add_done_callback(in_flight.discard)

            done = {t for t in in_flight if t.done()}
            in_flight -= done
            for t in done:
                if t.exception():
                    logger.error("Task raised: %s", t.exception())

        logger.info("Shutting down — %d in-flight tasks", len(in_flight))
        if in_flight:
            await asyncio.gather(*in_flight, return_exceptions=True)

    try:
        await amaas.grpc.aio.quit(scan_handle)
    except Exception:
        pass

    _complete_lifecycle_action()
    logger.info("Shutdown complete")


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()

import asyncio
import json
import logging
import os
import signal
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

import amaas.grpc.aio
import boto3
from aiobotocore.session import AioSession

logger = logging.getLogger("scanner")
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    level=os.environ.get("LOG_LEVEL", "INFO"),
)

QUARANTINE_BUCKET = os.environ.get("QUARANTINE_BUCKET", "")


# ── SG Discovery ────────────────────────────────────────────────────

def _discover_sgs():
    """Discover running SG instances via EC2 tags, return list of (ip, name)."""
    tag_key, tag_value = os.environ["SG_DISCOVERY_TAG"].split("=", 1)
    ec2 = boto3.client("ec2")
    resp = ec2.describe_instances(Filters=[
        {"Name": f"tag:{tag_key}", "Values": [tag_value]},
        {"Name": "instance-state-name", "Values": ["running"]},
    ])
    sgs = []
    for res in resp["Reservations"]:
        for inst in res["Instances"]:
            ip = inst.get("PrivateIpAddress")
            if not ip:
                continue
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            name = tags.get("Name", inst["InstanceId"])
            sgs.append((ip, name))
    sgs.sort(key=lambda x: x[1])
    return sgs


def _build_handles(api_key):
    """Create one SDK handle per discovered SG."""
    sgs = _discover_sgs()
    if not sgs:
        raise RuntimeError("No running SGs found")

    enable_tls = os.environ.get("ENABLE_TLS", "false").lower() == "true"
    cert_path = None
    if enable_tls:
        sm = boto3.client("secretsmanager")
        ca_cert_pem = sm.get_secret_value(SecretId=os.environ["SG_CA_CERT_SECRET_ARN"])["SecretString"]
        cert_path = "/tmp/sg-ca.pem"
        with open(cert_path, "w") as f:
            f.write(ca_cert_pem)

    handles = []
    for ip, name in sgs:
        if enable_tls:
            # Connect via DNS hostname so cert (*.sgi.xdr.trendmicro.com) validates
            host = f"{name.lower()}.sgi.xdr.trendmicro.com:443"
            handle = amaas.grpc.aio.init(host, api_key=api_key, enable_tls=True, ca_cert=cert_path)
        else:
            host = f"{ip}:80"
            handle = amaas.grpc.aio.init(host, api_key=api_key, enable_tls=False)
        handles.append((handle, name))
        logger.info("SDK handle: %s (%s)", name, host)
    return handles


# ── Core Scan Logic ──────────────────────────────────────────────────

async def _process_file(s3, scan_bucket, key, size, pml, feedback, handle, sg_name,
                        logs, audit_log_group):
    logger.info("Processing s3://%s/%s (%d bytes)", scan_bucket, key, size)

    try:
        resp = await s3.get_object(Bucket=scan_bucket, Key=key)
        async with resp["Body"] as stream:
            file_bytes = await stream.read()
    except Exception as exc:
        if "NoSuchKey" in str(type(exc).__name__) or "NoSuchKey" in str(exc):
            logger.warning("s3://%s/%s gone, skipping", scan_bucket, key)
            return
        raise

    # Scan with retry
    for attempt in range(3):
        scan_start = time.monotonic()
        try:
            result_json = await amaas.grpc.aio.scan_buffer(
                handle, file_bytes, os.path.basename(key),
                pml=pml, feedback=feedback, tags=["S3-Scan"],
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

    # Route based on verdict
    if is_malicious:
        malware_names = [m.get("malwareName", "") for m in result.get("foundMalwares", [])]
        logger.warning("MALICIOUS: s3://%s/%s malware=%s scan=%dms sg=%s",
                       scan_bucket, key, malware_names, scan_ms, sg_name)
        await s3.put_object_tagging(
            Bucket=scan_bucket, Key=key,
            Tagging={"TagSet": [
                {"Key": "ScanResult", "Value": "Malware"},
                {"Key": "ScanTimestamp", "Value": scan_ts},
            ]},
        )
        await s3.put_object(
            Bucket=QUARANTINE_BUCKET,
            Key=f"{scan_bucket}/{key}",
            Body=file_bytes,
            Tagging=urlencode({"ScanResult": "Malware", "ScanTimestamp": scan_ts}),
        )
        await s3.delete_object(Bucket=scan_bucket, Key=key)
        verdict = "malicious"
    else:
        logger.info("CLEAN: s3://%s/%s scan=%dms sg=%s", scan_bucket, key, scan_ms, sg_name)
        await s3.put_object_tagging(
            Bucket=scan_bucket, Key=key,
            Tagging={"TagSet": [
                {"Key": "ScanResult", "Value": "Clean"},
                {"Key": "ScanTimestamp", "Value": scan_ts},
            ]},
        )
        verdict = "clean"

    await _audit(logs, audit_log_group, scan_bucket, key, size, verdict,
                 result, scan_ms, sg_name)
    del file_bytes


# ── Audit Trail ──────────────────────────────────────────────────────

async def _audit(logs, log_group, bucket, key, size, verdict, result,
                 scan_ms, sg_name):
    if not log_group or not logs:
        return
    stream = f"scanner-{socket.gethostname()}"
    entry = {
        "timestamp": time.time(),
        "file": key,
        "bucket": bucket,
        "size": size,
        "verdict": verdict,
        "scanResult": result.get("scanResult", -1),
        "sha256": result.get("fileSHA256", ""),
        "malware": [m.get("malwareName", "") for m in result.get("foundMalwares", [])],
        "scanId": result.get("scanId", ""),
        "scanDurationMs": scan_ms,
        "serviceGateway": sg_name,
    }
    try:
        try:
            await logs.create_log_stream(logGroupName=log_group, logStreamName=stream)
        except Exception:
            pass  # Already exists
        await logs.put_log_events(
            logGroupName=log_group, logStreamName=stream,
            logEvents=[{"timestamp": int(time.time() * 1000), "message": json.dumps(entry)}],
        )
    except Exception:
        logger.warning("Audit write failed", exc_info=True)


# ── SQS Message Processing ──────────────────────────────────────────

async def _process_message(sqs, s3, logs, queue_url, message, handles,
                           scan_counter, visibility_timeout, pml, feedback,
                           audit_log_group):
    receipt_handle = message["ReceiptHandle"]

    async def heartbeat():
        interval = max(visibility_timeout - 60, 30)
        while True:
            await asyncio.sleep(interval)
            try:
                await sqs.change_message_visibility(
                    QueueUrl=queue_url, ReceiptHandle=receipt_handle,
                    VisibilityTimeout=visibility_timeout)
            except Exception:
                logger.warning("Failed to extend visibility", exc_info=True)
                return

    heartbeat_task = asyncio.create_task(heartbeat())
    try:
        body = json.loads(message["Body"])
        record = body.get("Records", [{}])[0].get("s3", {})
        scan_bucket = record.get("bucket", {}).get("name")
        key = record.get("object", {}).get("key")
        size = record.get("object", {}).get("size", 0)

        if not scan_bucket or not key:
            logger.error("Missing bucket/key in event: %s", json.dumps(body)[:200])
            await sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
            return

        # Round-robin across SG handles
        idx = scan_counter[0] % len(handles)
        scan_counter[0] += 1
        handle, sg_name = handles[idx]

        await _process_file(s3, scan_bucket, key, size, pml, feedback, handle, sg_name,
                            logs, audit_log_group)
        await sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)

    except Exception:
        logger.exception("Failed processing message %s", message.get("MessageId", "?"))
        try:
            await sqs.change_message_visibility(
                QueueUrl=queue_url, ReceiptHandle=receipt_handle,
                VisibilityTimeout=30)
        except Exception:
            pass
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


# ── Main ─────────────────────────────────────────────────────────────

async def async_main():
    shutdown_event = asyncio.Event()
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGTERM, shutdown_event.set)
    loop.add_signal_handler(signal.SIGINT, shutdown_event.set)

    queue_url = os.environ["SQS_QUEUE_URL"]
    visibility_timeout = int(os.environ.get("SQS_VISIBILITY_TIMEOUT", "300"))
    sg_refresh_interval = int(os.environ.get("SG_REFRESH_INTERVAL", "60"))
    pml = os.environ.get("PML_ENABLED", "true").lower() == "true"
    feedback = os.environ.get("FEEDBACK_ENABLED", "true").lower() == "true"
    audit_log_group = os.environ.get("AUDIT_LOG_GROUP", "")

    sm = boto3.client("secretsmanager")
    api_key = sm.get_secret_value(SecretId=os.environ["V1FS_API_KEY_SECRET_ARN"])["SecretString"]

    handles = _build_handles(api_key)
    scan_counter = [0]  # mutable counter for round-robin

    # Dynamic concurrency: 1.5× total SG handler capacity
    concurrency = max(int(len(handles) * 32 * 1.5), 1)
    semaphore = asyncio.Semaphore(concurrency)

    logger.info("Scanner starting — queue=%s concurrency=%d handles=%d",
                queue_url, concurrency, len(handles))

    session = AioSession()
    async with session.create_client("sqs") as sqs, \
               session.create_client("s3") as s3, \
               session.create_client("logs") as logs:

        in_flight: set[asyncio.Task] = set()
        last_sg_refresh = time.monotonic()
        consecutive_errors = 0

        async def guarded_process(message):
            async with semaphore:
                await _process_message(sqs, s3, logs, queue_url, message,
                                       handles, scan_counter, visibility_timeout,
                                       pml, feedback, audit_log_group)

        while not shutdown_event.is_set():
            # Periodic SG refresh
            if time.monotonic() - last_sg_refresh > sg_refresh_interval:
                last_sg_refresh = time.monotonic()
                try:
                    new_sgs = set(sg[1] for sg in _discover_sgs())
                    old_sgs = set(name for _, name in handles)
                    if new_sgs != old_sgs:
                        logger.info("SG set changed: %s → %s", sorted(old_sgs), sorted(new_sgs))
                        old_handles = handles
                        handles = _build_handles(api_key)
                        concurrency = max(int(len(handles) * 32 * 1.5), 1)
                        semaphore = asyncio.Semaphore(concurrency)
                        logger.info("Concurrency adjusted to %d for %d SGs", concurrency, len(handles))
                        for h, _ in old_handles:
                            try:
                                await amaas.grpc.aio.quit(h)
                            except Exception:
                                pass
                except Exception:
                    logger.warning("SG refresh failed", exc_info=True)

            # Backpressure
            if len(in_flight) >= concurrency * 2:
                await asyncio.sleep(0.1)
                in_flight -= {t for t in in_flight if t.done()}
                continue

            # Poll SQS
            try:
                resp = await sqs.receive_message(
                    QueueUrl=queue_url, MaxNumberOfMessages=10,
                    WaitTimeSeconds=20, AttributeNames=["All"])
                consecutive_errors = 0
            except Exception:
                consecutive_errors += 1
                delay = min(2 ** consecutive_errors, 60)
                logger.exception("SQS error, retrying in %.1fs", delay)
                await asyncio.sleep(delay)
                continue

            for msg in resp.get("Messages", []):
                task = asyncio.create_task(guarded_process(msg))
                in_flight.add(task)
                task.add_done_callback(in_flight.discard)

            in_flight -= {t for t in in_flight if t.done()}

        # Graceful shutdown
        logger.info("Shutting down — %d in-flight tasks", len(in_flight))
        if in_flight:
            await asyncio.gather(*in_flight, return_exceptions=True)

    for handle, _ in handles:
        try:
            await amaas.grpc.aio.quit(handle)
        except Exception:
            pass

    logger.info("Shutdown complete")


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()

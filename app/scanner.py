import json
import logging
import os
import random
import time
import urllib.parse

import boto3
import grpc
import amaas.grpc

logger = logging.getLogger("scanner")
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Module-level state — persists across warm invocations
_channels = None
_channel_addrs = None
_channel_failures = None  # Circuit breaker: failure count per channel
_channel_cooldown = None  # Circuit breaker: cooldown expiry per channel
_channels_built_at = 0.0  # monotonic timestamp of last channel build
_s3_client = None
_ec2_client = None
_logs_client = None
_audit_stream_created = False

# Channel refresh interval — re-discover SGs periodically
CHANNEL_REFRESH_SECONDS = 60

# Circuit breaker settings
CB_FAILURE_THRESHOLD = 3  # failures before marking channel unhealthy
CB_COOLDOWN_SECONDS = 60  # seconds to skip an unhealthy channel


def _get_s3():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3")
    return _s3_client


def _get_ec2():
    global _ec2_client
    if _ec2_client is None:
        _ec2_client = boto3.client("ec2")
    return _ec2_client


def _get_logs():
    global _logs_client
    if _logs_client is None:
        _logs_client = boto3.client("logs")
    return _logs_client


def _discover_sg_addresses():
    """Discover running Service Gateway IPs via EC2 tags."""
    tag_spec = os.environ.get("SG_DISCOVERY_TAG", "")
    if not tag_spec:
        raise RuntimeError("SG_DISCOVERY_TAG not set")

    tag_key, tag_value = tag_spec.split("=", 1)
    ec2 = _get_ec2()
    resp = ec2.describe_instances(Filters=[
        {"Name": f"tag:{tag_key}", "Values": [tag_value]},
        {"Name": "instance-state-name", "Values": ["running"]},
    ])

    addrs = []
    for res in resp["Reservations"]:
        for inst in res["Instances"]:
            addrs.append(f"{inst['PrivateIpAddress']}:443")

    if not addrs:
        raise RuntimeError("No running Service Gateway instances found")

    addrs.sort()  # deterministic order for channel stability
    return addrs


def _build_channels():
    global _channels, _channel_addrs, _channel_failures, _channel_cooldown, _channels_built_at

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
    options = [
        ("grpc.ssl_target_name_override", tls_override),
        ("grpc.max_send_message_length", 512 * 1024 * 1024),
        ("grpc.max_receive_message_length", 512 * 1024 * 1024),
        ("grpc.keepalive_time_ms", 30_000),
        ("grpc.keepalive_timeout_ms", 10_000),
        ("grpc.keepalive_permit_without_calls", 1),
    ]

    addrs = _discover_sg_addresses()
    channels_per_sg = int(os.environ.get("CHANNELS_PER_SG", "1"))
    channels = []
    channel_addrs = []
    for addr in addrs:
        for c in range(channels_per_sg):
            ch = grpc.secure_channel(addr, composite, options=options)
            channels.append(ch)
            channel_addrs.append(addr)
        logger.info("Created %d gRPC channel(s) to %s", channels_per_sg, addr)

    _channels = channels
    _channel_addrs = channel_addrs
    _channel_failures = [0] * len(channels)
    _channel_cooldown = [0.0] * len(channels)
    _channels_built_at = time.monotonic()


def _get_channel():
    """Return a healthy gRPC channel with circuit breaker logic."""
    if _channels is None or (time.monotonic() - _channels_built_at > CHANNEL_REFRESH_SECONDS):
        _build_channels()
    if len(_channels) == 1:
        return _channels[0], _channel_addrs[0], 0

    now = time.monotonic()
    healthy = [i for i in range(len(_channels))
               if _channel_failures[i] < CB_FAILURE_THRESHOLD or now >= _channel_cooldown[i]]

    if not healthy:
        # All channels unhealthy — reset cooldowns and try any
        logger.warning("All gRPC channels unhealthy, resetting circuit breakers")
        for i in range(len(_channels)):
            _channel_failures[i] = 0
            _channel_cooldown[i] = 0.0
        healthy = list(range(len(_channels)))

    idx = random.choice(healthy)
    # Reset failure count if cooldown expired (probe the channel)
    if _channel_failures[idx] >= CB_FAILURE_THRESHOLD and now >= _channel_cooldown[idx]:
        _channel_failures[idx] = 0
    return _channels[idx], _channel_addrs[idx], idx


def _mark_channel_success(idx):
    """Reset failure count on successful scan."""
    if _channel_failures is not None and idx < len(_channel_failures):
        _channel_failures[idx] = 0


def _mark_channel_failure(idx):
    """Increment failure count and set cooldown if threshold reached."""
    if _channel_failures is not None and idx < len(_channel_failures):
        _channel_failures[idx] += 1
        if _channel_failures[idx] >= CB_FAILURE_THRESHOLD:
            _channel_cooldown[idx] = time.monotonic() + CB_COOLDOWN_SECONDS
            logger.warning("Circuit breaker OPEN for channel %d (%s) — cooldown %ds",
                           idx, _channel_addrs[idx], CB_COOLDOWN_SECONDS)


# ── Handler ──────────────────────────────────────────────────────────

def handler(event, context):
    s3 = _get_s3()
    clean_bucket = os.environ["S3_CLEAN_BUCKET"]
    quarantine_bucket = os.environ["S3_QUARANTINE_BUCKET"]
    pml = os.environ.get("PML_ENABLED", "true").lower() == "true"
    feedback = os.environ.get("FEEDBACK_ENABLED", "true").lower() == "true"
    audit_log_group = os.environ.get("AUDIT_LOG_GROUP", "")

    failures = []
    for sqs_record in event.get("Records", []):
        try:
            body = json.loads(sqs_record["body"])
            for s3_event in body.get("Records", []):
                _process_record(
                    s3_event, s3, clean_bucket, quarantine_bucket,
                    pml, feedback, audit_log_group,
                )
        except Exception:
            logger.exception("Failed processing SQS message %s", sqs_record.get("messageId", "?"))
            failures.append({"itemIdentifier": sqs_record["messageId"]})

    if failures:
        return {"batchItemFailures": failures}
    return {"batchItemFailures": []}


def _process_record(
    record, s3, clean_bucket, quarantine_bucket,
    pml, feedback, audit_log_group,
):
    s3_data = record.get("s3", {})
    bucket = s3_data.get("bucket", {}).get("name")
    key_encoded = s3_data.get("object", {}).get("key")
    if not bucket or not key_encoded:
        logger.error("Malformed S3 record, skipping")
        return

    key = urllib.parse.unquote_plus(key_encoded)
    size = s3_data.get("object", {}).get("size", 0)
    logger.info("Processing s3://%s/%s (%d bytes)", bucket, key, size)

    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        file_bytes = resp["Body"].read()
    except s3.exceptions.NoSuchKey:
        logger.warning("s3://%s/%s gone, skipping", bucket, key)
        return

    channel, sg_addr, ch_idx = _get_channel()
    scan_start = time.monotonic()
    try:
        result_json = amaas.grpc.scan_buffer(
            channel, file_bytes, os.path.basename(key),
            tags=["S3-Scan"], pml=pml, feedback=feedback,
        )
        _mark_channel_success(ch_idx)
    except Exception:
        _mark_channel_failure(ch_idx)
        raise
    scan_ms = int((time.monotonic() - scan_start) * 1000)
    result = json.loads(result_json)
    is_malicious = result.get("scanResult", 0) > 0

    if is_malicious:
        dest_bucket = quarantine_bucket
        verdict = "malicious"
        tag = "Malware"
        malware_names = [m.get("malwareName", "") for m in result.get("foundMalwares", [])]
        logger.warning(
            "MALICIOUS: s3://%s/%s malware=%s scan=%dms sg=%s",
            bucket, key, malware_names, scan_ms, sg_addr,
        )
    else:
        dest_bucket = clean_bucket
        verdict = "clean"
        tag = "Clean"
        logger.info("CLEAN: s3://%s/%s scan=%dms sg=%s", bucket, key, scan_ms, sg_addr)

    s3.put_object(Bucket=dest_bucket, Key=key, Body=file_bytes, Tagging=f"ScanResult={tag}")
    s3.delete_object(Bucket=bucket, Key=key)
    _audit(audit_log_group, key, size, verdict, result, scan_ms, sg_addr)
    del file_bytes


def _audit(log_group, key, size, verdict, result, scan_ms, sg_addr):
    global _audit_stream_created
    if not log_group:
        return
    try:
        logs = _get_logs()
        stream = f"scanner-{os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown')}"
        if not _audit_stream_created:
            try:
                logs.create_log_stream(logGroupName=log_group, logStreamName=stream)
            except (logs.exceptions.ResourceAlreadyExistsException, Exception):
                pass
            _audit_stream_created = True
        entry = {
            "timestamp": time.time(),
            "file": key,
            "size": size,
            "verdict": verdict,
            "scanResult": result.get("scanResult", -1),
            "sha256": result.get("fileSHA256", ""),
            "malware": [m.get("malwareName", "") for m in result.get("foundMalwares", [])],
            "scanId": result.get("scanId", ""),
            "scanDurationMs": scan_ms,
            "serviceGateway": sg_addr,
        }
        logs.put_log_events(
            logGroupName=log_group, logStreamName=stream,
            logEvents=[{"timestamp": int(time.time() * 1000), "message": json.dumps(entry)}],
        )
    except Exception:
        logger.warning("Audit write failed", exc_info=True)

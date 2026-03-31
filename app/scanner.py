import json
import logging
import os
import random
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

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
_ssm_client = None
_logs_client = None
_sts_client = None
_audit_stream_created = False
_registered_sources = set()  # Source buckets we've already registered in SSM

# Cross-account support
SCANNER_ACCOUNT_ID = os.environ.get("SCANNER_ACCOUNT_ID", "")
QUARANTINE_BUCKET = os.environ.get("QUARANTINE_BUCKET", "")
CUSTOMER_LOG_GROUP = os.environ.get("CUSTOMER_LOG_GROUP", "v1fs-scan-audit")
CROSS_ACCOUNT_ROLE_NAME = "appliance-v1fs-scanner-access"
_cross_account_creds = {}  # Cache: account_id → (creds_dict, expiry_monotonic)
_cross_account_s3_clients = {}  # Cache: account_id → s3_client
_cross_account_logs_clients = {}  # Cache: account_id → logs_client
_registered_cross_account = set()  # Cross-account buckets already registered in SSM

# SSM parameters
ENROLLED_BUCKETS_PARAM = "/appliance-v1fs/enrolled-buckets"
CROSS_ACCOUNT_BUCKETS_PARAM = "/appliance-v1fs/cross-account-buckets"

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


def _get_ssm():
    global _ssm_client
    if _ssm_client is None:
        _ssm_client = boto3.client("ssm")
    return _ssm_client


def _get_logs():
    global _logs_client
    if _logs_client is None:
        _logs_client = boto3.client("logs")
    return _logs_client


def _get_sts():
    global _sts_client
    if _sts_client is None:
        _sts_client = boto3.client("sts")
    return _sts_client


def _get_cross_account_creds(account_id):
    """Assume cross-account role and cache temporary credentials."""
    now = time.monotonic()
    if account_id in _cross_account_creds:
        creds, expiry = _cross_account_creds[account_id]
        if now < expiry:
            return creds

    role_arn = f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE_NAME}"
    resp = _get_sts().assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"scanner-{account_id}",
        DurationSeconds=3600,
    )
    creds = {
        "aws_access_key_id": resp["Credentials"]["AccessKeyId"],
        "aws_secret_access_key": resp["Credentials"]["SecretAccessKey"],
        "aws_session_token": resp["Credentials"]["SessionToken"],
    }
    # Cache with 55-minute expiry (5 min before 1-hour STS expiry)
    _cross_account_creds[account_id] = (creds, now + 3300)
    # Invalidate any cached clients so they get recreated with new creds
    _cross_account_s3_clients.pop(account_id, None)
    _cross_account_logs_clients.pop(account_id, None)
    logger.info("Assumed role %s for account %s", role_arn, account_id)
    return creds


def _get_cross_account_s3(account_id):
    """Return an S3 client for a cross-account role."""
    if account_id not in _cross_account_s3_clients:
        creds = _get_cross_account_creds(account_id)
        _cross_account_s3_clients[account_id] = boto3.client("s3", **creds)
    return _cross_account_s3_clients[account_id]


def _get_cross_account_logs(account_id):
    """Return a CloudWatch Logs client for a cross-account role."""
    if account_id not in _cross_account_logs_clients:
        creds = _get_cross_account_creds(account_id)
        _cross_account_logs_clients[account_id] = boto3.client("logs", **creds)
    return _cross_account_logs_clients[account_id]


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
    max_file_bytes = int(os.environ.get("MAX_FILE_SIZE_MB", "500")) * 1024 * 1024
    options = [
        ("grpc.ssl_target_name_override", tls_override),
        ("grpc.max_send_message_length", max_file_bytes),
        ("grpc.max_receive_message_length", max_file_bytes),
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


# ── Bucket Management ──────────────────────────────────────────────

def _register_source_bucket(bucket_name):
    """Add a source bucket to the SSM enrolled-buckets registry if not already tracked."""
    if bucket_name in _registered_sources:
        return
    ssm = _get_ssm()
    try:
        resp = ssm.get_parameter(Name=ENROLLED_BUCKETS_PARAM)
        current = set(resp["Parameter"]["Value"].split(","))
    except ssm.exceptions.ParameterNotFound:
        current = set()
    if bucket_name not in current:
        current.add(bucket_name)
        ssm.put_parameter(
            Name=ENROLLED_BUCKETS_PARAM,
            Value=",".join(sorted(current)),
            Type="String",
            Overwrite=True,
        )
        logger.info("Registered source bucket: %s", bucket_name)
    _registered_sources.add(bucket_name)


def _register_cross_account_bucket(account_id, bucket_name):
    """Register a cross-account bucket in SSM for reconciliation tracking."""
    key = f"{account_id}:{bucket_name}"
    if key in _registered_cross_account:
        return
    ssm = _get_ssm()
    try:
        resp = ssm.get_parameter(Name=CROSS_ACCOUNT_BUCKETS_PARAM)
        buckets = json.loads(resp["Parameter"]["Value"])
    except (ssm.exceptions.ParameterNotFound, json.JSONDecodeError):
        buckets = {}
    account_buckets = set(buckets.get(account_id, []))
    if bucket_name not in account_buckets:
        account_buckets.add(bucket_name)
        buckets[account_id] = sorted(account_buckets)
        ssm.put_parameter(
            Name=CROSS_ACCOUNT_BUCKETS_PARAM,
            Value=json.dumps(buckets),
            Type="String",
            Overwrite=True,
        )
        logger.info("Registered cross-account bucket: %s:%s", account_id, bucket_name)
    _registered_cross_account.add(key)


# ── Handler ──────────────────────────────────────────────────────────

def handler(event, context):
    local_s3 = _get_s3()
    pml = os.environ.get("PML_ENABLED", "true").lower() == "true"
    feedback = os.environ.get("FEEDBACK_ENABLED", "true").lower() == "true"
    audit_log_group = os.environ.get("AUDIT_LOG_GROUP", "")

    failures = []
    for sqs_record in event.get("Records", []):
        try:
            body = json.loads(sqs_record["body"])
            # EventBridge event format: detail.bucket.name, detail.object.key
            detail = body.get("detail", {})
            bucket = detail.get("bucket", {}).get("name")
            key = detail.get("object", {}).get("key")
            size = detail.get("object", {}).get("size", 0)
            source_account = body.get("account", SCANNER_ACCOUNT_ID)

            if bucket and key:
                is_cross_account = (
                    source_account
                    and SCANNER_ACCOUNT_ID
                    and source_account != SCANNER_ACCOUNT_ID
                )
                source_s3 = _get_cross_account_s3(source_account) if is_cross_account else local_s3
                _process_file(
                    source_s3, local_s3, bucket, key, size,
                    source_account, is_cross_account,
                    pml, feedback, audit_log_group,
                )
            else:
                logger.error("Missing bucket/key in event: %s", json.dumps(body)[:500])
        except Exception:
            logger.exception("Failed processing SQS message %s", sqs_record.get("messageId", "?"))
            failures.append({"itemIdentifier": sqs_record["messageId"]})

    if failures:
        return {"batchItemFailures": failures}
    return {"batchItemFailures": []}


def _process_file(source_s3, local_s3, bucket, key, size,
                   source_account, is_cross_account,
                   pml, feedback, audit_log_group):
    if is_cross_account:
        _register_cross_account_bucket(source_account, bucket)
    else:
        _register_source_bucket(bucket)
    logger.info("Processing s3://%s/%s (%d bytes) account=%s", bucket, key, size, source_account)

    try:
        resp = source_s3.get_object(Bucket=bucket, Key=key)
        file_bytes = resp["Body"].read()
    except source_s3.exceptions.NoSuchKey:
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
    scan_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if is_malicious:
        malware_names = [m.get("malwareName", "") for m in result.get("foundMalwares", [])]
        logger.warning(
            "MALICIOUS: s3://%s/%s malware=%s scan=%dms sg=%s account=%s",
            bucket, key, malware_names, scan_ms, sg_addr, source_account,
        )
        # Move to central quarantine bucket with metadata tags
        quarantine_key = f"{source_account}/{bucket}/{key}"
        tags = urlencode({
            "ScanResult": "Malware",
            "ScanTimestamp": scan_ts,
            "SourceAccount": source_account,
            "SourceBucket": bucket,
        })
        local_s3.put_object(
            Bucket=QUARANTINE_BUCKET, Key=quarantine_key,
            Body=file_bytes, Tagging=tags,
        )
        source_s3.delete_object(Bucket=bucket, Key=key)
        verdict = "malicious"
    else:
        logger.info("CLEAN: s3://%s/%s scan=%dms sg=%s account=%s",
                     bucket, key, scan_ms, sg_addr, source_account)
        # Tag clean file in place — leave it in the source bucket
        source_s3.put_object_tagging(
            Bucket=bucket, Key=key,
            Tagging={"TagSet": [
                {"Key": "ScanResult", "Value": "Clean"},
                {"Key": "ScanTimestamp", "Value": scan_ts},
            ]},
        )
        verdict = "clean"

    _audit(audit_log_group, bucket, key, size, verdict, result, scan_ms, sg_addr, source_account)
    del file_bytes


_customer_audit_streams = set()  # Tracks which cross-account log streams we've created


def _audit(log_group, bucket, key, size, verdict, result, scan_ms, sg_addr, source_account):
    global _audit_stream_created
    if not log_group:
        return
    stream = f"scanner-{os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown')}"
    entry = {
        "timestamp": time.time(),
        "file": key,
        "bucket": bucket,
        "sourceAccount": source_account,
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

    # Write to scanner-account audit log
    try:
        logs = _get_logs()
        if not _audit_stream_created:
            try:
                logs.create_log_stream(logGroupName=log_group, logStreamName=stream)
            except Exception:
                pass
            _audit_stream_created = True
        logs.put_log_events(logGroupName=log_group, logStreamName=stream, logEvents=log_event)
    except Exception:
        logger.warning("Audit write failed (scanner account)", exc_info=True)

    # Write to customer-account audit log for cross-account scans
    if source_account and SCANNER_ACCOUNT_ID and source_account != SCANNER_ACCOUNT_ID:
        try:
            xacct_logs = _get_cross_account_logs(source_account)
            if source_account not in _customer_audit_streams:
                try:
                    xacct_logs.create_log_stream(
                        logGroupName=CUSTOMER_LOG_GROUP, logStreamName=stream)
                except Exception:
                    pass
                _customer_audit_streams.add(source_account)
            xacct_logs.put_log_events(
                logGroupName=CUSTOMER_LOG_GROUP, logStreamName=stream, logEvents=log_event)
        except Exception:
            logger.warning("Audit write failed (customer account %s)", source_account, exc_info=True)

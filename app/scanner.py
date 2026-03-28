import json
import logging
import os
import random
import time
import urllib.parse
import uuid

import boto3
import grpc
import amaas.grpc

logger = logging.getLogger("scanner")
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# gRPC file size threshold — files larger than this use EFS mount point scanning
GRPC_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# EFS mount point scanning
EFS_MOUNT_PATH = os.environ.get("EFS_MOUNT_PATH", "/mnt/efs")
EFS_QUARANTINE_DIR = "quarantine"
EFS_SCAN_POLL_INTERVAL = 2  # seconds between polls
EFS_SCAN_TIMEOUT = 300  # max seconds to wait for mount point scanner

# Module-level state — persists across warm invocations
_channels = None
_channel_addrs = None
_channel_failures = None  # Circuit breaker: failure count per channel
_channel_cooldown = None  # Circuit breaker: cooldown expiry per channel
_s3_client = None
_logs_client = None
_audit_stream_created = False
_efs_initialized = False

# Circuit breaker settings
CB_FAILURE_THRESHOLD = 3  # failures before marking channel unhealthy
CB_COOLDOWN_SECONDS = 60  # seconds to skip an unhealthy channel


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
    global _channels, _channel_addrs, _channel_failures, _channel_cooldown

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

    addrs = [a.strip() for a in os.environ["SG_ADDRESS"].split(",") if a.strip()]
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


def _get_channel():
    """Return a healthy gRPC channel with circuit breaker logic."""
    if _channels is None:
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


# ── EFS Mount Point Scanning ────────────────────────────────────────

def _ensure_efs_dirs():
    """Create the quarantine subdirectory on EFS if it doesn't exist."""
    global _efs_initialized
    if _efs_initialized:
        return
    quarantine_path = os.path.join(EFS_MOUNT_PATH, EFS_QUARANTINE_DIR)
    os.makedirs(quarantine_path, exist_ok=True)
    _efs_initialized = True


def _scan_via_efs(s3, bucket, key, size, clean_bucket, quarantine_bucket, audit_log_group):
    """Scan a large file via EFS mount point (NFS scanning by the Service Gateway).

    Flow:
    1. Download file from S3 to EFS /mnt/efs/{unique_id}_{filename}
    2. SG's mount point scanner detects the new file and scans it
    3. If malicious: scanner moves file to /mnt/efs/quarantine/
    4. If clean: file remains at original path
    5. Poll until file disappears from original path or appears in quarantine
    6. Route to appropriate S3 bucket and clean up EFS
    """
    _ensure_efs_dirs()

    filename = os.path.basename(key)
    scan_id = uuid.uuid4().hex[:12]
    efs_filename = f"{scan_id}_{filename}"
    efs_path = os.path.join(EFS_MOUNT_PATH, efs_filename)
    quarantine_path = os.path.join(EFS_MOUNT_PATH, EFS_QUARANTINE_DIR, efs_filename)

    # Download from S3 directly to EFS (streaming, no memory buffering)
    logger.info("EFS scan: downloading s3://%s/%s to %s", bucket, key, efs_path)
    scan_start = time.monotonic()
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        with open(efs_path, "wb") as f:
            for chunk in resp["Body"].iter_chunks(chunk_size=1024 * 1024):
                f.write(chunk)
    except s3.exceptions.NoSuchKey:
        logger.warning("s3://%s/%s gone, skipping", bucket, key)
        return
    except Exception:
        # Clean up partial file
        try:
            os.unlink(efs_path)
        except OSError:
            pass
        raise

    download_ms = int((time.monotonic() - scan_start) * 1000)
    logger.info("EFS scan: downloaded %d bytes in %dms, waiting for scanner", size, download_ms)

    # Poll for scan completion
    # The mount point scanner will either:
    # - Move the file to quarantine/ (malicious)
    # - Leave it in place (clean) — we detect this by file mtime stabilizing
    verdict = None
    poll_start = time.monotonic()

    while time.monotonic() - poll_start < EFS_SCAN_TIMEOUT:
        time.sleep(EFS_SCAN_POLL_INTERVAL)

        # Check if file was moved to quarantine
        if os.path.exists(quarantine_path):
            verdict = "malicious"
            logger.warning("EFS scan: MALICIOUS (quarantined) %s", efs_filename)
            break

        # Check if file still exists at original path
        if not os.path.exists(efs_path):
            # File disappeared but not in quarantine — scanner may have moved it elsewhere
            verdict = "malicious"
            logger.warning("EFS scan: file disappeared (assumed malicious) %s", efs_filename)
            break

        # File still at original path — check if scan is complete
        # The scanner modifies the file's access time during scanning.
        # If the file hasn't been accessed in the last poll interval, scan is likely done.
        try:
            stat = os.stat(efs_path)
            age_since_modify = time.time() - stat.st_mtime
            # If file hasn't been modified for 2x poll interval, consider scan complete
            if age_since_modify > EFS_SCAN_POLL_INTERVAL * 3 and (time.monotonic() - poll_start) > 10:
                verdict = "clean"
                logger.info("EFS scan: CLEAN (stable) %s after %.0fs", efs_filename, time.monotonic() - poll_start)
                break
        except OSError:
            pass

    scan_ms = int((time.monotonic() - scan_start) * 1000)

    if verdict is None:
        logger.error("EFS scan: timeout after %ds for %s", EFS_SCAN_TIMEOUT, efs_filename)
        verdict = "clean"  # Default to clean on timeout to avoid blocking

    # Route to S3
    result = {"scanResult": 1 if verdict == "malicious" else 0}

    if verdict == "malicious":
        tag = "Malware"
        # Upload from quarantine path (or original if it disappeared)
        src_path = quarantine_path if os.path.exists(quarantine_path) else None
        if src_path:
            with open(src_path, "rb") as f:
                s3.put_object(Bucket=quarantine_bucket, Key=key, Body=f, Tagging="ScanResult=Malware")
        else:
            # File gone entirely — copy from S3 ingest to quarantine via server-side copy
            s3.copy_object(
                Bucket=quarantine_bucket, Key=key,
                CopySource={"Bucket": bucket, "Key": key},
                Tagging="ScanResult=Malware", TaggingDirective="REPLACE",
            )
    else:
        tag = "Clean"
        with open(efs_path, "rb") as f:
            s3.put_object(Bucket=clean_bucket, Key=key, Body=f, Tagging="ScanResult=Clean")

    # Delete from ingest
    s3.delete_object(Bucket=bucket, Key=key)

    # Clean up EFS
    for p in [efs_path, quarantine_path]:
        try:
            os.unlink(p)
        except OSError:
            pass

    _audit(audit_log_group, key, size, verdict, result, scan_ms, "EFS-mount")
    logger.info("EFS scan: %s %s scan=%dms (download=%dms)", verdict.upper(), key, scan_ms, download_ms)


# ── Handler ──────────────────────────────────────────────────────────

def handler(event, context):
    _ensure_efs_dirs()
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

    # Large files → EFS mount point scanning (NFS, supports PML, no size limit)
    if size > GRPC_MAX_FILE_SIZE:
        _scan_via_efs(s3, bucket, key, size, clean_bucket, quarantine_bucket, audit_log_group)
        return

    # Small files → gRPC (fast, through nginx ingress)
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

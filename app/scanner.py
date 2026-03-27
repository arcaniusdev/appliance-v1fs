import json
import logging
import os
import random
import socket
import time
import urllib.parse

import boto3
import grpc
import amaas.grpc

logger = logging.getLogger("scanner")
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# gRPC file size threshold — files larger than this use ICAP
GRPC_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ICAP_PORT = 1344  # ICAP on Service Gateway (iptables DNAT to scanner pod)

# Module-level state — persists across warm invocations
_channels = None
_channel_addrs = None
_sg_hosts = None
_s3_client = None
_logs_client = None
_audit_stream_created = False


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
    global _channels, _channel_addrs, _sg_hosts

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

    # SG_ADDRESS supports single or comma-separated addresses (host:port)
    addrs = [a.strip() for a in os.environ["SG_ADDRESS"].split(",") if a.strip()]
    channels_per_sg = int(os.environ.get("CHANNELS_PER_SG", "1"))
    channels = []
    channel_addrs = []
    sg_hosts = []
    for addr in addrs:
        host = addr.split(":")[0]
        if host not in sg_hosts:
            sg_hosts.append(host)
        for c in range(channels_per_sg):
            ch = grpc.secure_channel(addr, composite, options=options)
            channels.append(ch)
            channel_addrs.append(addr)
        logger.info("Created %d gRPC channel(s) to %s", channels_per_sg, addr)

    _channels = channels
    _channel_addrs = channel_addrs
    _sg_hosts = sg_hosts


def _get_channel():
    """Return a gRPC channel, picking randomly when multiple are configured."""
    if _channels is None:
        _build_channels()
    if len(_channels) == 1:
        return _channels[0], _channel_addrs[0]
    idx = random.randrange(len(_channels))
    return _channels[idx], _channel_addrs[idx]


def _get_sg_host():
    """Return a random SG host IP for ICAP scanning."""
    if _sg_hosts is None:
        _build_channels()
    return random.choice(_sg_hosts)


# ── ICAP Client ─────────────────────────────────────────────────────

def _scan_icap(file_bytes, filename, sg_host, api_key):
    """Scan a file via ICAP RESPMOD on the Service Gateway."""
    body = file_bytes
    body_len = len(body)

    # Build the encapsulated HTTP response (what ICAP RESPMOD wraps)
    http_resp_hdr = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {body_len}\r\n"
        f"\r\n"
    ).encode()

    encapsulated = f"res-hdr=0, res-body={len(http_resp_hdr)}"

    # Build the ICAP RESPMOD request
    icap_headers = (
        f"RESPMOD icap://{sg_host}:{ICAP_PORT}/avscan ICAP/1.0\r\n"
        f"Host: {sg_host}\r\n"
        f"X-scan-file-name: {filename}\r\n"
        f"Authorization: Bearer {api_key}\r\n"
        f"Encapsulated: {encapsulated}\r\n"
        f"\r\n"
    ).encode()

    # Chunked body encoding for ICAP
    chunk_header = f"{body_len:x}\r\n".encode()
    chunk_trailer = b"\r\n0\r\n\r\n"

    # Send request
    sock = socket.create_connection((sg_host, ICAP_PORT), timeout=300)
    try:
        sock.sendall(icap_headers + http_resp_hdr + chunk_header + body + chunk_trailer)

        # Read response
        response = b""
        while True:
            data = sock.recv(8192)
            if not data:
                break
            response += data
            # ICAP responses end with \r\n\r\n for headers-only (204)
            # or contain a full body for error responses
            if b"\r\n\r\n" in response and (
                response.startswith(b"ICAP/1.0 204") or
                b"</html>" in response.lower() or
                len(response) > 10000
            ):
                break
    finally:
        sock.close()

    resp_str = response.decode("utf-8", errors="replace")
    icap_status_line = resp_str.split("\r\n")[0]
    logger.info("ICAP response: %s (file=%s, sg=%s)", icap_status_line, filename, sg_host)

    # Parse ICAP status
    if "ICAP/1.0 204" in resp_str:
        return {"verdict": "clean", "scanResult": 0}
    elif "ICAP/1.0 200" in resp_str:
        if "403" in resp_str and "Virus Detected" in resp_str:
            return {"verdict": "malicious", "scanResult": 1}
        elif "400" in resp_str:
            logger.warning("ICAP 400: %s", resp_str[:500])
            raise RuntimeError(f"ICAP bad request: {resp_str[:300]}")
        elif "401" in resp_str:
            raise RuntimeError(f"ICAP auth failed: {resp_str[:300]}")
        elif "500" in resp_str:
            # Parse scan errors
            errors = []
            for code, msg in [("-69", "zip file count"), ("-71", "compression ratio"),
                              ("-76", "file too large"), ("-78", "compressed layers"),
                              ("-92", "password protected")]:
                if code in resp_str:
                    errors.append(msg)
            if errors:
                logger.warning("ICAP scan errors: %s", errors)
            return {"verdict": "clean", "scanResult": 0, "foundErrors": errors}
        else:
            logger.info("ICAP 200 (clean): %s", resp_str[:200])
            return {"verdict": "clean", "scanResult": 0}
    else:
        raise RuntimeError(f"Unexpected ICAP response: {icap_status_line}")


# ── API Key Cache ────────────────────────────────────────────────────

_api_key = None

def _get_api_key():
    global _api_key
    if _api_key is None:
        sm = boto3.client("secretsmanager")
        _api_key = sm.get_secret_value(
            SecretId=os.environ["V1FS_API_KEY_SECRET_ARN"]
        )["SecretString"]
    return _api_key


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

    # Download
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        file_bytes = resp["Body"].read()
    except s3.exceptions.NoSuchKey:
        logger.warning("s3://%s/%s gone, skipping", bucket, key)
        return

    # Scan — gRPC for small files, ICAP for large files
    scan_start = time.monotonic()

    if len(file_bytes) <= GRPC_MAX_FILE_SIZE:
        # gRPC path
        channel, sg_addr = _get_channel()
        result_json = amaas.grpc.scan_buffer(
            channel, file_bytes, os.path.basename(key),
            tags=["S3-Scan"], pml=pml, feedback=feedback,
        )
        result = json.loads(result_json)
        is_malicious = result.get("scanResult", 0) > 0
        scan_method = "gRPC"
    else:
        # ICAP path for large files
        sg_host = _get_sg_host()
        sg_addr = f"{sg_host}:{ICAP_PORT}"
        api_key = _get_api_key()
        result = _scan_icap(file_bytes, os.path.basename(key), sg_host, api_key)
        is_malicious = result.get("scanResult", 0) > 0
        has_decomp_errors = bool(result.get("foundErrors"))
        scan_method = "ICAP"

    scan_ms = int((time.monotonic() - scan_start) * 1000)

    if is_malicious:
        dest_bucket = quarantine_bucket
        verdict = "malicious"
        tag = "Malware"
        malware_names = [m.get("malwareName", "") for m in result.get("foundMalwares", [])]
        logger.warning(
            "MALICIOUS: s3://%s/%s malware=%s scan=%dms sg=%s method=%s",
            bucket, key, malware_names, scan_ms, sg_addr, scan_method,
        )
    elif scan_method == "ICAP" and has_decomp_errors:
        dest_bucket = quarantine_bucket
        verdict = "decomp_violation"
        tag = "DecompViolation"
        logger.warning(
            "DECOMP_VIOLATION: s3://%s/%s errors=%s scan=%dms sg=%s",
            bucket, key, result.get("foundErrors"), scan_ms, sg_addr,
        )
    else:
        dest_bucket = clean_bucket
        verdict = "clean"
        tag = "Clean"
        logger.info("CLEAN: s3://%s/%s scan=%dms sg=%s method=%s", bucket, key, scan_ms, sg_addr, scan_method)

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

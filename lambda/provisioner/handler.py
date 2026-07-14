import json
import logging
import os
import re
import time

import boto3
import paramiko

from ssh_helper import ClishSession

logger = logging.getLogger()
logger.setLevel(logging.INFO)

VERSION_PARAM_PREFIX = "/appliance-v1fs/scanner-version/"
_SAFE_HOSTNAME = re.compile(r'^[A-Za-z0-9\-]{1,63}$')

# Deployment gates (Custom::AwaitRegistration / Custom::AwaitInstallation).
# Registration is automated; the File Security install is a manual console step
# and a freshly launched appliance may first self-upgrade its firmware, so the
# installation gate gets a much longer deadline.
GATE_DEADLINES = {"registration": 25 * 60, "installation": 90 * 60}
GATE_POLL_SECONDS = 30
GATE_REINVOKE_MARGIN_MS = 120 * 1000  # re-invoke self when <2 min of runtime left


def _validate_hostname(hostname):
    if not _SAFE_HOSTNAME.match(hostname):
        raise ValueError(f"Invalid hostname: {hostname!r}")
    return hostname


def handler(event, context):
    """Service Gateway provisioner.

    All appliance access is over SSH — the documented root path (KB-0014380):
    connect as ``admin`` with the launch key pair for clish operations, then
    authorize a generated key via ``configure verify cli support`` and connect
    as ``sgowner`` for root operations. This does NOT depend on the SSM agent,
    which the appliance's firmware self-upgrade removes; the ``sgowner`` key is
    installed through the appliance's own supported mechanism, so it survives.
    (SSM Parameter Store is still used to read the launch key and track scanner
    versions — that's an AWS API, unrelated to the on-appliance agent.)

    Two entry points share the provisioning logic:
    * Scheduled watchdog (EventBridge, every 15 min).
    * CloudFormation custom resource gate — blocks stack creation until the
      fleet reaches a target state, driving the watchdog directly.
    """
    if isinstance(event, dict) and "RequestType" in event and "ResponseURL" in event:
        return _handle_gate(event, context)
    return _handle_watchdog(event, context)


# ── SSH / root helpers ────────────────────────────────────────────────

def _get_ssh_key(key_pair_id, region):
    """Read the EC2 launch key pair's private key from SSM Parameter Store.

    CloudFormation-created AWS::EC2::KeyPair stores its private key at
    /ec2/keypair/<KeyPairId>. This is the ``admin`` SSH credential.
    """
    ssm = boto3.client("ssm", region_name=region)
    return ssm.get_parameter(
        Name=f"/ec2/keypair/{key_pair_id}", WithDecryption=True
    )["Parameter"]["Value"]


def _get_sgowner_session(host, port, admin_key, rsa_key, pubkey_b64):
    """Authorize a temp key via admin clish, return a root (sgowner) SSH client."""
    with ClishSession(host, "admin", admin_key, port=port) as session:
        session.connect(timeout=30)
        session.send_command("enable", expect="# ", timeout=15)
        session.send_command(
            f"configure verify cli support {pubkey_b64}", expect="# ", timeout=30)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username="sgowner", pkey=rsa_key,
                   timeout=30, allow_agent=False, look_for_keys=False)
    return client


def _run(client, cmd, timeout=15):
    """Run a command on a root SSH client, return stripped stdout."""
    _stdin, stdout, _stderr = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace").strip()


def _extract_cert(client):
    """Extract the SG's TLS CA cert via openssl over the root session."""
    out = _run(client,
               "openssl s_client -connect localhost:443 "
               "-servername sg.sgi.xdr.trendmicro.com </dev/null 2>/dev/null "
               "| openssl x509", timeout=30)
    if "-----BEGIN CERTIFICATE-----" in out and "-----END CERTIFICATE-----" in out:
        start = out.index("-----BEGIN CERTIFICATE-----")
        end = out.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
        return out[start:end] + "\n"
    return None


def _store_cert(secret_name, cert_pem, region):
    sm = boto3.client("secretsmanager", region_name=region)
    try:
        sm.create_secret(Name=secret_name, SecretString=cert_pem,
                         Description="Service Gateway self-signed CA certificate (PEM)")
        logger.info("CA cert stored: %s", secret_name)
    except sm.exceptions.ResourceExistsException:
        sm.put_secret_value(SecretId=secret_name, SecretString=cert_pem)
        logger.info("CA cert updated: %s", secret_name)


def _get_scanner_version(client):
    return _run(client,
                "sudo microk8s kubectl get pod -n sg-sfs-scanner "
                "-o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null",
                timeout=15).strip("'")


def _patch_nginx_body_size(client):
    """Raise nginx proxy-body-size to MaxFileSizeMB — only when the live value differs."""
    desired = f"{os.environ.get('MAX_FILE_SIZE_MB', '500')}m"
    current = _run(client,
                   "sudo microk8s kubectl -n ingress get configmap "
                   "nginx-load-balancer-microk8s-conf "
                   "-o jsonpath='{.data.proxy-body-size}' 2>/dev/null",
                   timeout=15).strip("'\n ")
    if current == desired:
        logger.info("nginx proxy-body-size already %s", desired)
        return
    out = _run(client,
               "sudo microk8s kubectl -n ingress patch configmap "
               "nginx-load-balancer-microk8s-conf --type merge "
               f"-p '{{\"data\":{{\"proxy-body-size\":\"{desired}\"}}}}' 2>&1", timeout=15)
    logger.info("nginx proxy-body-size patched %s -> %s: %s",
                current or "(default)", desired, out)


def _set_scan_cache(client):
    """Override TM_AM_SCAN_CACHE only when disabled for baseline testing; else default."""
    enabled = os.environ.get("SCAN_CACHE_ENABLED", "true")
    env = "TM_AM_SCAN_CACHE=false" if enabled == "false" else "TM_AM_SCAN_CACHE-"
    out = _run(client,
               f"sudo microk8s kubectl set env deployment --all "
               f"-n sg-sfs-scanner {env} 2>&1", timeout=15)
    logger.info("scan cache (%s): %s", env, out)


def _harden_ciphers(host, port, admin_key):
    """Disable weak/legacy TLS ciphers via the documented clish command."""
    with ClishSession(host, "admin", admin_key, port=port) as session:
        session.connect(timeout=30)
        session.send_command("enable", expect="# ", timeout=15)
        session.send_command(
            "configure nginx-ingress-controller-cipher disable-weak",
            expect="# ", timeout=60)
    logger.info("weak TLS ciphers disabled on %s", host)


def _scanner_pod_running(host, port, admin_key):
    """Check via admin clish whether the File Security scanner pod is Running."""
    with ClishSession(host, "admin", admin_key, port=port) as session:
        session.connect(timeout=30)
        session.send_command("enable", expect="# ", timeout=15)
        out = session.send_command("configure verify plat", expect="# ", timeout=60)
    return "sg-sfs-scanner" in out and "Running" in out


# ── Discovery ─────────────────────────────────────────────────────────

def _discover_sg_instances(region):
    tag_key = os.environ.get("SG_TAG_KEY", "appliance-v1fs:stack")
    tag_value = os.environ.get("SG_TAG_VALUE", "")
    if not tag_value:
        return []
    ec2 = boto3.client("ec2", region_name=region)
    resp = ec2.describe_instances(Filters=[
        {"Name": f"tag:{tag_key}", "Values": [tag_value]},
        {"Name": "instance-state-name", "Values": ["running"]},
    ])
    instances = []
    for res in resp["Reservations"]:
        for inst in res["Instances"]:
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            instances.append({
                "instance_id": inst["InstanceId"],
                "hostname": tags.get("Name", inst["InstanceId"]),
                "private_ip": inst.get("PrivateIpAddress", ""),
                "registered": tags.get("appliance-v1fs:registered", "false"),
                "provisioned": tags.get("appliance-v1fs:provisioned", "false"),
            })
    instances.sort(key=lambda x: x["hostname"])
    return instances


# ── Watchdog ──────────────────────────────────────────────────────────

def _handle_watchdog(event, context):
    """Full SG lifecycle over SSH.

    Per appliance:
    1. Not registered → set hostname (sgowner), name endpoint + register (admin
       clish), tag registered.
    2. Registered but scanner pod not Running → wait (File Security is installed
       from the Vision One console).
    3. Scanner pod Running, not provisioned → harden ciphers, patch nginx if
       needed, set scan cache, extract CA cert, record version, tag provisioned.
    4. Already provisioned → re-extract cert if the scanner version changed.
    """
    region = event.get("region", os.environ.get("AWS_REGION_NAME", "us-east-1"))
    sg_instances = _discover_sg_instances(region)
    key_pair_id = os.environ.get("KEY_PAIR_ID", "")
    cert_secret = os.environ.get("CERT_SECRET_NAME", "appliance-v1fs/sg-ca-cert")

    if not sg_instances or not key_pair_id:
        logger.warning("Watchdog: no SG instances or no KEY_PAIR_ID")
        return {"status": "skipped", "reason": "missing config"}

    admin_key = _get_ssh_key(key_pair_id, region)
    ssm = boto3.client("ssm", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)

    # One authorized key per invocation, reused for all sgowner sessions.
    rsa_key = paramiko.RSAKey.generate(4096)
    pubkey_b64 = rsa_key.get_base64()

    results = []
    for inst in sg_instances:
        iid = inst["instance_id"]
        host = inst.get("private_ip", "")
        port = 22
        logger.info("Watchdog: checking %s (%s)", iid, inst["hostname"])
        if not host:
            logger.warning("Watchdog: no private IP for %s", iid)
            results.append({"instance": iid, "action": "error"})
            continue
        try:
            param_name = f"{VERSION_PARAM_PREFIX}{iid}"
            try:
                stored = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
            except ssm.exceptions.ParameterNotFound:
                stored = ""

            # ── Step 1: register if not yet registered ──────────────
            if inst["registered"] != "true":
                logger.info("Watchdog: %s not registered", iid)
                try:
                    with ClishSession(host, "admin", admin_key, port=port) as session:
                        banner = session.connect(timeout=30)

                    if "Status: Registered" not in banner:
                        hostname = _validate_hostname(inst["hostname"])
                        logger.info("Watchdog: setting hostname to %s", hostname)
                        sgowner = _get_sgowner_session(host, port, admin_key, rsa_key, pubkey_b64)
                        _run(sgowner, f"sudo hostnamectl set-hostname {hostname}", timeout=15)
                        sgowner.close()

                        with ClishSession(host, "admin", admin_key, port=port) as session:
                            session.connect(timeout=30)
                            session.send_command("enable", expect="# ", timeout=15)
                            session.send_command(f"configure endpoint {hostname}",
                                                 expect="# ", timeout=30)

                        sm = boto3.client("secretsmanager", region_name=region)
                        token_secret = os.environ.get(
                            "REGISTRATION_TOKEN_SECRET", "appliance-v1fs/sg-registration-token")
                        token = sm.get_secret_value(SecretId=token_secret)["SecretString"]

                        for attempt in range(3):
                            logger.info("Watchdog: registering %s (attempt %d/3)", iid, attempt + 1)
                            with ClishSession(host, "admin", admin_key, port=port) as session:
                                session.connect(timeout=30)
                                session.send_command("enable", expect="# ", timeout=15)
                                reg_out = session.send_command(f"register {token}",
                                                               expect="# ", timeout=300)
                            if "Try again later" not in reg_out:
                                break
                            logger.warning("Watchdog: register blocked, retrying in 30s")
                            time.sleep(30)

                        time.sleep(30)
                        with ClishSession(host, "admin", admin_key, port=port) as session:
                            banner = session.connect(timeout=30)
                        if "Status: Registered" not in banner:
                            logger.warning("Watchdog: %s registration not confirmed", iid)
                            results.append({"instance": iid, "action": "registering"})
                            continue
                        logger.info("Watchdog: %s registered", iid)

                    ec2.create_tags(Resources=[iid], Tags=[
                        {"Key": "appliance-v1fs:registered", "Value": "true"}])
                except Exception:
                    logger.warning("Watchdog: registration failed for %s", iid, exc_info=True)
                    results.append({"instance": iid, "action": "registration_failed"})
                    continue

            # ── Step 2: wait for the scanner pod ────────────────────
            if not _scanner_pod_running(host, port, admin_key):
                logger.info("Watchdog: %s — scanner pod not running yet", iid)
                results.append({"instance": iid, "action": "waiting"})
                continue

            # ── Step 3: re-apply customizations (root) ──────────────
            client = _get_sgowner_session(host, port, admin_key, rsa_key, pubkey_b64)
            try:
                _patch_nginx_body_size(client)
                _set_scan_cache(client)
                current_version = _get_scanner_version(client)

                # ── Step 4: complete provisioning or check for updates ──
                if inst["provisioned"] != "true":
                    logger.info("Watchdog: completing provisioning for %s (%s)", iid, inst["hostname"])
                    try:
                        _harden_ciphers(host, port, admin_key)
                    except Exception:
                        logger.warning("Watchdog: cipher hardening failed on %s", iid, exc_info=True)
                    cert_pem = _extract_cert(client)
                    if cert_pem:
                        _store_cert(cert_secret, cert_pem, region)
                    ssm.put_parameter(Name=param_name, Value=current_version,
                                      Type="String", Overwrite=True)
                    ec2.create_tags(Resources=[iid], Tags=[
                        {"Key": "appliance-v1fs:provisioned", "Value": "true"}])
                    results.append({"instance": iid, "action": "provisioned"})
                    logger.info("Watchdog: %s (%s) now fully provisioned", iid, inst["hostname"])
                elif current_version != stored:
                    logger.info("Watchdog: version changed on %s: %s -> %s",
                                iid, stored or "(none)", current_version)
                    cert_pem = _extract_cert(client)
                    if cert_pem:
                        _store_cert(cert_secret, cert_pem, region)
                        logger.info("Watchdog: CA cert re-extracted from %s", iid)
                    ssm.put_parameter(Name=param_name, Value=current_version,
                                      Type="String", Overwrite=True)
                    results.append({"instance": iid, "action": "updated",
                                    "oldVersion": stored, "newVersion": current_version})
                else:
                    logger.info("Watchdog: %s unchanged (%s)", iid, current_version)
                    results.append({"instance": iid, "action": "unchanged"})
            finally:
                client.close()
        except Exception:
            logger.exception("Watchdog: failed checking %s", iid)
            results.append({"instance": iid, "action": "error"})

    return {"status": "complete", "results": results}


# ── Deployment gates (CloudFormation custom resource) ─────────────────

def _cfn_respond(event, status, data=None, reason=None, physical_id=None):
    body = json.dumps({
        "Status": status,
        "Reason": reason or "See CloudWatch logs for the provisioner Lambda",
        "PhysicalResourceId": physical_id or event.get("PhysicalResourceId")
                              or event.get("LogicalResourceId", "gate"),
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "Data": data or {},
    }).encode("utf-8")
    import urllib.request
    from urllib.parse import urlparse
    url = event["ResponseURL"]
    host = urlparse(url).hostname or ""
    logger.info("cfnresponse: %s PUT to host=%s (RequestType=%s)",
                status, host, event.get("RequestType"))
    req = urllib.request.Request(url, data=body, method="PUT")
    req.add_header("content-type", "")
    req.add_header("content-length", str(len(body)))
    # The response URL is an S3 presigned PUT reached (in the VPC) via the S3
    # gateway endpoint. During stack DELETE that path can be momentarily flaky
    # as networking tears down, so retry a few times before giving up — a lost
    # response leaves the stack stuck in DELETE_FAILED.
    last_exc = None
    for attempt in range(5):
        try:
            urllib.request.urlopen(req, timeout=15)
            logger.info("cfnresponse PUT succeeded on attempt %d", attempt + 1)
            return
        except Exception as exc:
            last_exc = exc
            logger.warning("cfnresponse PUT attempt %d failed: %r", attempt + 1, exc)
            _diagnose_connectivity(host)
            time.sleep(3 * (attempt + 1))
    logger.error("cfnresponse PUT failed after retries: %r", last_exc)
    raise last_exc


def _diagnose_connectivity(host):
    """Log DNS + TCP-connect probes so a failed cfnresponse tells us WHY:
    DNS failure vs no route/timeout vs connection refused."""
    import socket
    if not host:
        return
    try:
        ip = socket.gethostbyname(host)
        logger.warning("diag: DNS %s -> %s OK", host, ip)
    except Exception as exc:
        logger.warning("diag: DNS resolution of %s FAILED: %r", host, exc)
        return
    for port in (443,):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        try:
            s.connect((ip, port))
            logger.warning("diag: TCP connect %s:%d OK", ip, port)
        except Exception as exc:
            logger.warning("diag: TCP connect %s:%d FAILED: %r", ip, port, exc)
        finally:
            s.close()


def _count_ready(region, tag_key):
    return sum(1 for inst in _discover_sg_instances(region)
               if inst.get(tag_key) == "true")


def _drive_watchdog(phase, context):
    """Run one watchdog (SSH provisioning) pass.

    The gate Lambda runs OUTSIDE the VPC so its cfnresponse PUT always reaches
    S3 (a VPC Lambda cannot reliably reach S3 during stack teardown — the NAT /
    route path is torn down mid-delete, wedging the stack in DELETE_FAILED). SSH
    to the appliance needs the VPC, so the gate delegates each watchdog pass to
    the VPC-resident watchdog Lambda via a synchronous invoke (serialised, so
    passes don't overlap). WATCHDOG_FUNCTION_ARN unset ⇒ same-Lambda fallback.
    """
    wd_arn = os.environ.get("WATCHDOG_FUNCTION_ARN")
    if not wd_arn:
        try:
            _handle_watchdog({}, context)
        except Exception:
            logger.exception("Gate(%s): in-process watchdog pass failed", phase)
        return
    try:
        from botocore.config import Config
        cfg = Config(connect_timeout=10, read_timeout=300, retries={"max_attempts": 0})
        boto3.client("lambda", config=cfg).invoke(
            FunctionName=wd_arn, InvocationType="RequestResponse", Payload=b"{}")
    except Exception:
        # A slow/failed watchdog pass must not stop the gate; it retries next poll.
        logger.exception("Gate(%s): watchdog invoke failed, will retry", phase)


def _handle_gate(event, context):
    """Block a CloudFormation stack until the fleet reaches a target state.

    Phase 'registration' waits for all appliances to register; 'installation'
    waits for File Security to be installed (via console) and provisioned. Each
    poll drives a watchdog pass. To outlast the Lambda timeout, the function
    re-invokes itself asynchronously carrying an absolute deadline.
    """
    if event["RequestType"] == "Delete":
        _cfn_respond(event, "SUCCESS")
        return

    props = event.get("ResourceProperties", {})
    phase = props.get("Phase", "registration")
    expected = int(props.get("ExpectedCount", "1"))
    region = event.get("region", os.environ.get("AWS_REGION_NAME", "us-east-1"))
    tag_key = "registered" if phase == "registration" else "provisioned"

    deadline = event.get("_deadline")
    if deadline is None:
        deadline = time.time() + GATE_DEADLINES.get(phase, 25 * 60)
        event["_deadline"] = deadline

    try:
        while True:
            _drive_watchdog(phase, context)

            ready = _count_ready(region, tag_key)
            logger.info("Gate(%s): %d/%d appliances ready", phase, ready, expected)
            if ready >= expected:
                _cfn_respond(event, "SUCCESS", {"Ready": str(ready), "Phase": phase})
                return
            if time.time() >= deadline:
                _cfn_respond(event, "FAILED", reason=(
                    f"{ready}/{expected} appliances reached '{tag_key}' before timeout. "
                    + ("Check the registration token and provisioner logs."
                       if phase == "registration"
                       else "Install File Security on each appliance in the Vision One "
                            "console (Service Gateway Management > Manage Services).")))
                return
            if context.get_remaining_time_in_millis() < GATE_REINVOKE_MARGIN_MS:
                boto3.client("lambda").invoke(
                    FunctionName=context.invoked_function_arn,
                    InvocationType="Event",
                    Payload=json.dumps(event).encode("utf-8"))
                logger.info("Gate(%s): re-invoking self to continue waiting", phase)
                return
            time.sleep(GATE_POLL_SECONDS)
    except Exception as exc:
        logger.exception("Gate(%s): unexpected error", phase)
        _cfn_respond(event, "FAILED", reason=f"Gate error: {exc}")

import json
import logging
import os
import re
import time
import urllib.request

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

VERSION_PARAM_PREFIX = "/appliance-v1fs/scanner-version/"
_SAFE_HOSTNAME = re.compile(r'^[A-Za-z0-9\-]{1,63}$')

# Deployment gates (Custom::AwaitRegistration / Custom::AwaitInstallation).
# The registration wait is fully automated; the File Security install wait
# depends on a human console step, so it gets a much longer deadline.
# installation allows 90 min: a freshly launched appliance may first
# self-upgrade its firmware to the newest release (delivered over-the-air by
# Vision One, independent of the AMI) before File Security can be installed.
GATE_DEADLINES = {"registration": 25 * 60, "installation": 90 * 60}
GATE_POLL_SECONDS = 30
GATE_REINVOKE_MARGIN_MS = 120 * 1000  # re-invoke self when <2 min of runtime left


def _validate_hostname(hostname):
    if not _SAFE_HOSTNAME.match(hostname):
        raise ValueError(f"Invalid hostname: {hostname!r}")
    return hostname


def handler(event, context):
    """Service Gateway provisioner.

    Two entry points share the registration/provisioning logic:
    * Scheduled watchdog (EventBridge, every 15 min) — the steady-state driver.
    * CloudFormation custom resource — blocks stack creation until the fleet
      reaches a target state (all registered, then all provisioned), driving
      the watchdog itself so the stack doesn't wait on the 15-min schedule.
    """
    if isinstance(event, dict) and "RequestType" in event and "ResponseURL" in event:
        return _handle_gate(event, context)
    return _handle_watchdog(event, context)


# ── SSM helpers ──────────────────────────────────────────────────────

def _ssm_run(ssm, instance_id, commands, timeout=120):
    """Run shell commands on an instance via SSM RunShellScript. Returns stdout."""
    resp = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        TimeoutSeconds=timeout,
    )
    cmd_id = resp["Command"]["CommandId"]
    deadline = time.time() + timeout + 30
    while time.time() < deadline:
        time.sleep(3)
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except Exception:
            continue
        status = inv["Status"]
        if status in ("Success", "Failed", "TimedOut", "Cancelled", "DeliveryTimedOut"):
            out = inv.get("StandardOutputContent", "")
            err = inv.get("StandardErrorContent", "")
            if status != "Success":
                raise RuntimeError(f"SSM {status}:\n{err or out}")
            return out
    raise TimeoutError(f"SSM poll timed out after {timeout}s")


def _clish(ssm, instance_id, *commands, timeout=60):
    """Run clish commands on the SG via a temp script file executed through SSM."""
    cmd_file = "/tmp/.clish_cmds"
    shell = [f"rm -f {cmd_file}"]
    for cmd in commands:
        safe = cmd.replace("'", r"'\''")
        shell.append(f"printf '%s\\n' '{safe}' >> {cmd_file}")
    shell.append(f"clish -u admin {cmd_file} 2>&1")
    shell.append(f"rm -f {cmd_file}")
    return _ssm_run(ssm, instance_id, shell, timeout=timeout)


# ── Secrets helpers ──────────────────────────────────────────────────

def _store_cert(secret_name, cert_pem, region):
    """Store or update the SG CA cert in Secrets Manager."""
    sm = boto3.client("secretsmanager", region_name=region)
    try:
        sm.create_secret(
            Name=secret_name,
            Description="Service Gateway self-signed CA certificate (PEM)",
            SecretString=cert_pem,
        )
        logger.info("CA cert stored: %s", secret_name)
    except sm.exceptions.ResourceExistsException:
        sm.put_secret_value(SecretId=secret_name, SecretString=cert_pem)
        logger.info("CA cert updated: %s", secret_name)


def _extract_cert(ssm, instance_id):
    """Extract the CA cert from the SG nginx TLS endpoint via SSM."""
    out = _ssm_run(ssm, instance_id, [
        "openssl s_client -connect localhost:443 "
        "-servername sg.sgi.xdr.trendmicro.com </dev/null 2>/dev/null | openssl x509"
    ], timeout=30)
    if "-----BEGIN CERTIFICATE-----" in out and "-----END CERTIFICATE-----" in out:
        start = out.index("-----BEGIN CERTIFICATE-----")
        end = out.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
        return out[start:end] + "\n"
    return None


# ── Discovery ─────────────────────────────────────────────────────────

def _discover_sg_instances(region):
    """Discover running SG instances tagged with the current stack."""
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
                "registered": tags.get("appliance-v1fs:registered", "false"),
                "provisioned": tags.get("appliance-v1fs:provisioned", "false"),
            })
    instances.sort(key=lambda x: x["hostname"])
    return instances


# ── Watchdog ──────────────────────────────────────────────────────────

def _handle_watchdog(event, context):
    """Periodic provisioner — handles the full SG lifecycle.

    For each SG instance:
    1. Not registered → set hostname, register with Vision One, tag
    2. Registered but no scanner pod → wait (FS must be installed via V1 console)
    3. Scanner pod running but not provisioned → harden ciphers, extract cert,
       patch nginx if needed, tag
    4. Already provisioned → check scanner version, re-extract cert if changed
    """
    region = event.get("region", os.environ.get("AWS_REGION_NAME", "us-east-1"))
    sg_instances = _discover_sg_instances(region)
    cert_secret = os.environ.get("CERT_SECRET_NAME", "appliance-v1fs/sg-ca-cert")

    if not sg_instances:
        logger.warning("Watchdog: no SG instances found")
        return {"status": "skipped", "reason": "no instances"}

    ssm = boto3.client("ssm", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    results = []

    for inst in sg_instances:
        iid = inst["instance_id"]
        logger.info("Watchdog: checking %s (%s)", iid, inst["hostname"])
        try:
            param_name = f"{VERSION_PARAM_PREFIX}{iid}"
            try:
                stored = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
            except ssm.exceptions.ParameterNotFound:
                stored = ""

            # ── Step 1: register if not yet registered ──────────────
            if inst["registered"] != "true":
                logger.info("Watchdog: %s not registered, checking banner", iid)
                try:
                    banner = _clish(ssm, iid, "show version", timeout=30)

                    if "Status: Registered" in banner:
                        logger.info("Watchdog: %s already registered (banner)", iid)
                    else:
                        hostname = _validate_hostname(inst["hostname"])
                        logger.info("Watchdog: setting hostname to %s", hostname)
                        _ssm_run(ssm, iid, [f"hostnamectl set-hostname {hostname}"], timeout=30)
                        _clish(ssm, iid, "enable", f"configure endpoint {hostname}", timeout=60)

                        sm = boto3.client("secretsmanager", region_name=region)
                        token_secret = os.environ.get(
                            "REGISTRATION_TOKEN_SECRET", "appliance-v1fs/sg-registration-token")
                        token = sm.get_secret_value(SecretId=token_secret)["SecretString"]

                        for attempt in range(3):
                            logger.info("Watchdog: registering %s (attempt %d/3)",
                                        iid, attempt + 1)
                            reg_out = _clish(ssm, iid, "enable", f"register {token}",
                                             timeout=300)
                            logger.info("Watchdog: register output len=%d", len(reg_out))
                            if "Try again later" not in reg_out:
                                break
                            logger.warning("Watchdog: register blocked, retrying in 30s")
                            time.sleep(30)

                        time.sleep(30)
                        banner = _clish(ssm, iid, "show version", timeout=30)
                        if "Status: Registered" not in banner:
                            logger.warning("Watchdog: %s registration not confirmed", iid)
                            results.append({"instance": iid, "action": "registering"})
                            continue
                        logger.info("Watchdog: %s registered successfully", iid)

                    ec2.create_tags(Resources=[iid], Tags=[
                        {"Key": "appliance-v1fs:registered", "Value": "true"},
                    ])
                except Exception:
                    logger.warning("Watchdog: registration failed for %s", iid, exc_info=True)
                    results.append({"instance": iid, "action": "registration_failed"})
                    continue

            # ── Step 2: wait for scanner pod ────────────────────────
            pod_out = _ssm_run(ssm, iid, [
                "kubectl get pods --all-namespaces 2>&1 | grep sg-sfs-scanner || true"
            ], timeout=30)
            scanner_running = "sg-sfs-scanner" in pod_out and "Running" in pod_out

            if not scanner_running:
                logger.info("Watchdog: %s — scanner pod not running yet", iid)
                results.append({"instance": iid, "action": "waiting"})
                continue

            # ── Step 3: re-apply customizations ────────────────────
            # nginx proxy-body-size: only patch when the live value differs.
            # If the appliance default ever grows to >= our target, this
            # stops touching the configmap entirely.
            max_size = os.environ.get("MAX_FILE_SIZE_MB", "500")
            desired_body_size = f"{max_size}m"
            current_body_size = _ssm_run(ssm, iid, [
                "kubectl -n ingress get configmap nginx-load-balancer-microk8s-conf "
                "-o jsonpath='{.data.proxy-body-size}' 2>/dev/null"
            ], timeout=30).strip("'\n ")
            if current_body_size != desired_body_size:
                nginx_out = _ssm_run(ssm, iid, [
                    f"kubectl -n ingress patch configmap nginx-load-balancer-microk8s-conf "
                    f"--type merge -p '{{\"data\":{{\"proxy-body-size\":\"{desired_body_size}\"}}}}' 2>&1"
                ], timeout=30)
                logger.info("nginx proxy-body-size patched %s -> %s: %s",
                            current_body_size or "(default)", desired_body_size,
                            nginx_out.strip())
            else:
                logger.info("nginx proxy-body-size already %s", desired_body_size)

            # Scan cache: the appliance default is enabled. Only override the
            # env var when the cache is explicitly disabled (baseline testing);
            # otherwise remove any override so the default applies.
            scan_cache = os.environ.get("SCAN_CACHE_ENABLED", "true")
            cache_env = "TM_AM_SCAN_CACHE=false" if scan_cache == "false" else "TM_AM_SCAN_CACHE-"
            cache_out = _ssm_run(ssm, iid, [
                f"kubectl set env deployment --all -n sg-sfs-scanner {cache_env} 2>&1"
            ], timeout=30)
            logger.info("scan cache (%s): %s", cache_env, cache_out.strip())

            version_out = _ssm_run(ssm, iid, [
                "kubectl get pod -n sg-sfs-scanner "
                "-o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null"
            ], timeout=30)
            current_version = version_out.strip("'\n ")

            # ── Step 4: complete provisioning or check for updates ──
            if inst["provisioned"] != "true":
                logger.info("Watchdog: completing provisioning for %s (%s)",
                            iid, inst["hostname"])
                try:
                    _clish(ssm, iid, "enable",
                           "configure nginx-ingress-controller-cipher disable-weak",
                           timeout=60)
                    logger.info("Watchdog: weak TLS ciphers disabled on %s", iid)
                except Exception:
                    logger.warning("Watchdog: cipher hardening failed on %s", iid,
                                   exc_info=True)
                cert_pem = _extract_cert(ssm, iid)
                if cert_pem:
                    _store_cert(cert_secret, cert_pem, region)
                ssm.put_parameter(Name=param_name, Value=current_version,
                                   Type="String", Overwrite=True)
                ec2.create_tags(Resources=[iid], Tags=[
                    {"Key": "appliance-v1fs:provisioned", "Value": "true"},
                ])
                results.append({"instance": iid, "action": "provisioned"})
                logger.info("Watchdog: %s (%s) now fully provisioned", iid, inst["hostname"])
            elif current_version != stored:
                logger.info("Watchdog: version changed on %s: %s -> %s",
                            iid, stored or "(none)", current_version)
                cert_pem = _extract_cert(ssm, iid)
                if cert_pem:
                    _store_cert(cert_secret, cert_pem, region)
                    logger.info("Watchdog: CA cert re-extracted from %s", iid)
                ssm.put_parameter(Name=param_name, Value=current_version,
                                   Type="String", Overwrite=True)
                results.append({
                    "instance": iid, "action": "updated",
                    "oldVersion": stored, "newVersion": current_version,
                })
            else:
                logger.info("Watchdog: %s unchanged (%s)", iid, current_version)
                results.append({"instance": iid, "action": "unchanged"})

        except Exception:
            logger.exception("Watchdog: failed checking %s", iid)
            results.append({"instance": iid, "action": "error"})

    return {"status": "complete", "results": results}


# ── Deployment gates (CloudFormation custom resource) ─────────────────

def _cfn_respond(event, status, data=None, reason=None, physical_id=None):
    """PUT a response to the CloudFormation pre-signed URL."""
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
    req = urllib.request.Request(event["ResponseURL"], data=body, method="PUT")
    req.add_header("content-type", "")
    req.add_header("content-length", str(len(body)))
    urllib.request.urlopen(req, timeout=15)


def _count_ready(region, tag_value):
    """How many discovered SG instances carry the given readiness tag = true."""
    ready = 0
    for inst in _discover_sg_instances(region):
        if inst.get(tag_value) == "true":
            ready += 1
    return ready


def _handle_gate(event, context):
    """Block a CloudFormation stack until the SG fleet reaches a target state.

    Phase 'registration' waits for all appliances to register with Vision One;
    phase 'installation' waits for File Security to be installed (via the
    console) and provisioned. Each poll drives a watchdog pass so progress does
    not depend on the 15-minute schedule. To outlast the Lambda timeout (the
    installation wait can take much longer than 15 min), the function
    re-invokes itself asynchronously, carrying an absolute deadline, until the
    target is met or the deadline passes — only then does it answer CFN.
    """
    if event["RequestType"] == "Delete":
        _cfn_respond(event, "SUCCESS")
        return

    props = event.get("ResourceProperties", {})
    phase = props.get("Phase", "registration")
    expected = int(props.get("ExpectedCount", "1"))
    region = event.get("region", os.environ.get("AWS_REGION_NAME", "us-east-1"))
    tag_key = "registered" if phase == "registration" else "provisioned"

    # Absolute deadline persists across self-reinvocations.
    deadline = event.get("_deadline")
    if deadline is None:
        deadline = time.time() + GATE_DEADLINES.get(phase, 25 * 60)
        event["_deadline"] = deadline

    try:
        while True:
            try:
                _handle_watchdog({}, context)
            except Exception:
                logger.exception("Gate(%s): watchdog pass failed, will retry", phase)

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

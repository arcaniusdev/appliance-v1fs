import datetime
import json
import logging
import os
import time

import boto3
import paramiko

from ssh_helper import ClishSession
from eice_tunnel import EICETunnel

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# SSM parameter for tracking scanner version per SG
VERSION_PARAM_PREFIX = "/appliance-v1fs/scanner-version/"
DASHBOARD_STATE_PARAM = "/appliance-v1fs/dashboard-state"
EXPECTED_REPLICAS = 4


def handler(event, context):
    """Service Gateway provisioner.

    Dispatches on event type:
      - widgetContext: CloudWatch custom widget (dashboard)
      - EC2 Instance State-change Notification: Provision a new SG
      - action=watchdog: Check SG versions, re-extract cert if changed
    """
    # CloudWatch custom widget → dashboard
    if "widgetContext" in event:
        return _handle_dashboard(event, context)

    # EventBridge EC2 state change → provision new SG
    detail_type = event.get("detail-type", "")
    if detail_type == "EC2 Instance State-change Notification":
        detail = event.get("detail", {})
        if detail.get("state") == "running":
            return _handle_instance_running(event, context)

    # Direct invoke (watchdog from EventBridge schedule)
    if "action" in event and event["action"] == "watchdog":
        return _handle_watchdog(event, context)

    logger.error("Unknown event type: %s", json.dumps(event)[:500])


# ── Helpers ──────────────────────────────────────────────────────────

def _get_ssh_key(key_pair_id: str, region: str) -> str:
    ssm = boto3.client("ssm", region_name=region)
    resp = ssm.get_parameter(
        Name=f"/ec2/keypair/{key_pair_id}",
        WithDecryption=True,
    )
    return resp["Parameter"]["Value"]


def _get_sgowner_session(tunnel, admin_key, rsa_key, pubkey_b64):
    """Install a temp SSH key via admin clish and return an sgowner SSH client."""
    host = "127.0.0.1"
    port = tunnel.local_port

    with ClishSession(host, "admin", admin_key, port=port) as session:
        session.connect(timeout=30)
        session.send_command("enable", expect="# ", timeout=15)
        session.send_command(
            f"configure verify cli support {pubkey_b64}",
            expect="# ",
            timeout=30,
        )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username="sgowner", pkey=rsa_key,
                   timeout=30, allow_agent=False, look_for_keys=False)
    return client


def _extract_cert(sgowner_client):
    """Extract the CA cert from the SG via openssl."""
    stdin, stdout, stderr = sgowner_client.exec_command(
        "openssl s_client -connect localhost:443 -servername sg.sgi.xdr.trendmicro.com "
        "</dev/null 2>/dev/null | openssl x509",
        timeout=30,
    )
    output = stdout.read().decode("utf-8", errors="replace")
    if "-----BEGIN CERTIFICATE-----" in output and "-----END CERTIFICATE-----" in output:
        start = output.index("-----BEGIN CERTIFICATE-----")
        end = output.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
        return output[start:end] + "\n"
    return None


def _get_scanner_version(sgowner_client):
    """Get the scanner pod image version from the SG."""
    stdin, stdout, stderr = sgowner_client.exec_command(
        "sudo microk8s kubectl get pod -n sg-sfs-scanner "
        "-o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null",
        timeout=15,
    )
    return stdout.read().decode().strip("'")


def _get_replica_count(sgowner_client):
    """Get ready/desired replica counts for the scanner deployment."""
    stdin, stdout, stderr = sgowner_client.exec_command(
        "sudo microk8s kubectl get deployment -n sg-sfs-scanner "
        "-o jsonpath='{.items[0].status.readyReplicas} {.items[0].spec.replicas}' 2>/dev/null",
        timeout=15,
    )
    output = stdout.read().decode().strip("'").strip()
    parts = output.split()
    if len(parts) == 2:
        try:
            return int(parts[0]), int(parts[1])
        except ValueError:
            pass
    return None, None


def _get_nginx_body_size(sgowner_client):
    """Get the current nginx proxy-body-size from the configmap."""
    stdin, stdout, stderr = sgowner_client.exec_command(
        "sudo microk8s kubectl -n ingress get configmap "
        "nginx-load-balancer-microk8s-conf "
        "-o jsonpath='{.data.proxy-body-size}' 2>/dev/null",
        timeout=15,
    )
    return stdout.read().decode().strip("'").strip()


def _scale_replicas(sgowner_client, count):
    """Scale the scanner deployment to the specified replica count."""
    stdin, stdout, stderr = sgowner_client.exec_command(
        f"sudo microk8s kubectl scale deployment --all "
        f"-n sg-sfs-scanner --replicas={count} 2>&1",
        timeout=15,
    )
    output = stdout.read().decode().strip()
    logger.info("Scale replicas to %d: %s", count, output)
    return output


def _store_cert(secret_name, cert_pem, region):
    """Store or update the CA cert in Secrets Manager."""
    sm = boto3.client("secretsmanager", region_name=region)
    try:
        sm.create_secret(
            Name=secret_name,
            Description="Service Gateway self-signed CA certificate (PEM)",
            SecretString=cert_pem,
        )
        logger.info("CA cert stored as new secret: %s", secret_name)
    except sm.exceptions.ResourceExistsException:
        sm.put_secret_value(SecretId=secret_name, SecretString=cert_pem)
        logger.info("CA cert updated in existing secret: %s", secret_name)


# ── Dynamic SG Discovery ─────────────────────────────────────────────

# ── EC2 State Change → Provision ────────────────────────────────────

def _handle_instance_running(event, context):
    """Provision a Service Gateway when it reaches running state.

    Triggered by EventBridge EC2 state-change events. Filters by tag
    to only provision instances belonging to this stack.
    """
    instance_id = event["detail"]["instance-id"]
    region = event.get("region", os.environ.get("AWS_REGION_NAME", "us-east-1"))

    # Check if this instance belongs to our stack
    tag_key = os.environ.get("SG_TAG_KEY", "appliance-v1fs:stack")
    tag_value = os.environ.get("SG_TAG_VALUE", "")
    ec2 = boto3.client("ec2", region_name=region)
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    instances = [i for r in resp["Reservations"] for i in r["Instances"]]
    if not instances:
        return {"status": "skipped", "reason": "instance not found"}

    tags = {t["Key"]: t["Value"] for t in instances[0].get("Tags", [])}
    if tags.get(tag_key) != tag_value:
        logger.debug("Instance %s not ours (tag %s=%s), skipping",
                      instance_id, tag_key, tags.get(tag_key))
        return {"status": "skipped", "reason": "not our instance"}

    # Skip if already provisioned
    if tags.get("appliance-v1fs:provisioned") == "true":
        logger.info("Instance %s already provisioned, skipping", instance_id)
        return {"status": "skipped", "reason": "already provisioned"}

    # Hostname comes from the Name tag set by CloudFormation
    hostname = tags.get("Name", instance_id)
    logger.info("Provisioning Service Gateway %s as %s", instance_id, hostname)
    endpoint_id = os.environ.get("EICE_ENDPOINT_ID", "")
    key_pair_id = os.environ.get("KEY_PAIR_ID", "")
    cert_secret_name = os.environ.get("CERT_SECRET_NAME", "appliance-v1fs/sg-ca-cert")

    try:
        # Get registration token from Secrets Manager
        sm = boto3.client("secretsmanager", region_name=region)
        token_secret = os.environ.get("REGISTRATION_TOKEN_SECRET", "appliance-v1fs/sg-registration-token")
        token = sm.get_secret_value(SecretId=token_secret)["SecretString"]

        private_key = _get_ssh_key(key_pair_id, region)

        # Single EICE tunnel for the entire provisioning flow
        with EICETunnel(instance_id, endpoint_id, remote_port=22) as tunnel:
            host = "127.0.0.1"
            port = tunnel.local_port

            _wait_for_admin_ready(host, private_key, port=port)

            # Set OS hostname via sgowner
            logger.info("Setting OS hostname to %s", hostname)
            rsa_key = paramiko.RSAKey.generate(4096)
            pubkey_b64 = rsa_key.get_base64()
            sgowner = _get_sgowner_session(tunnel, private_key, rsa_key, pubkey_b64)
            sgowner.exec_command(f"sudo hostnamectl set-hostname {hostname}", timeout=15)
            sgowner.close()

            # Set clish endpoint name
            with ClishSession(host, "admin", private_key, port=port) as session:
                session.connect(timeout=30)
                session.send_command("enable", expect="# ", timeout=15)
                session.send_command(
                    f"configure endpoint {hostname}",
                    expect="# ", timeout=30,
                )

            # Register with Vision One
            output = ""
            for reg_attempt in range(10):
                logger.info("Registering Service Gateway (attempt %d/10)", reg_attempt + 1)
                with ClishSession(host, "admin", private_key, port=port) as session:
                    session.connect(timeout=30)
                    session.send_command("enable", expect="# ", timeout=15)
                    output = session.send_command(
                        f"register {token}",
                        expect="# ", timeout=300,
                    )
                    logger.info("Register output: %s", output[-500:])

                if "Try again later" not in output:
                    break
                logger.warning("Register blocked, retrying in 30s (attempt %d/10)", reg_attempt + 1)
                time.sleep(30)
            else:
                raise RuntimeError(f"Register still blocked after 10 attempts: {output[-300:]}")

            # Verify registration
            banner = ""
            for verify_attempt in range(5):
                time.sleep(30)
                logger.info("Verifying registration via banner (attempt %d/5)", verify_attempt + 1)
                with ClishSession(host, "admin", private_key, port=port) as session:
                    banner = session.connect(timeout=30)
                if "Status: Registered" in banner:
                    break

            if "Status: Registered" not in banner:
                raise RuntimeError(f"Registration verification failed after retries. Banner: {banner[-500:]}")

            logger.info("Service Gateway %s registered as %s", instance_id, hostname)

            # Wait for File Security scanner pod to be running
            _wait_for_scanner_pod(host, private_key, port=port)

            # Extract CA cert and patch nginx for large file gRPC scanning
            sgowner = _get_sgowner_session(tunnel, private_key, rsa_key, pubkey_b64)
            cert_pem = _extract_cert(sgowner)
            version = _get_scanner_version(sgowner)
            _patch_nginx_body_size(sgowner)
            sgowner.close()

            if cert_pem:
                logger.info("CA cert extracted from %s (%d bytes)", instance_id, len(cert_pem))
                _store_cert(cert_secret_name, cert_pem, region)
            if version:
                ssm = boto3.client("ssm", region_name=region)
                ssm.put_parameter(
                    Name=f"{VERSION_PARAM_PREFIX}{instance_id}",
                    Value=version,
                    Type="String",
                    Overwrite=True,
                )
                logger.info("Scanner version on %s: %s", instance_id, version)

        # Mark as provisioned so we don't re-provision on restart
        ec2.create_tags(Resources=[instance_id], Tags=[
            {"Key": "appliance-v1fs:provisioned", "Value": "true"},
        ])

        return {"status": "provisioned", "instance": instance_id, "hostname": hostname}

    except Exception as e:
        logger.exception("Provisioning failed for %s: %s", instance_id, e)
        return {"status": "failed", "instance": instance_id, "error": str(e)}


def _patch_nginx_body_size(sgowner_client):
    """Patch the nginx configmap to allow large file gRPC scanning.

    The default proxy-body-size of 10m blocks files >10MB. This patches it
    to match the MaxFileSizeMB template parameter. The watchdog re-applies
    every 15 minutes in case a scanner pod update reverts the configmap.
    """
    max_size = os.environ.get("MAX_FILE_SIZE_MB", "500")
    cmd = (
        "sudo microk8s kubectl -n ingress patch configmap "
        "nginx-load-balancer-microk8s-conf --type merge "
        f"-p '{{\"data\":{{\"proxy-body-size\":\"{max_size}m\"}}}}' 2>&1"
    )
    stdin, stdout, stderr = sgowner_client.exec_command(cmd, timeout=15)
    output = stdout.read().decode().strip()
    if "patched" in output or "unchanged" in output:
        logger.info("nginx proxy-body-size patched: %s", output)
    else:
        logger.warning("nginx patch may have failed: %s", output)


def _wait_for_scanner_pod(host, private_key, port=22, max_attempts=20, interval=15):
    """Poll until the File Security scanner pod is running on the SG."""
    for attempt in range(max_attempts):
        logger.info("Waiting for scanner pod (attempt %d/%d)", attempt + 1, max_attempts)
        try:
            with ClishSession(host, "admin", private_key, port=port) as session:
                session.connect(timeout=30)
                session.send_command("enable", expect="# ", timeout=15)
                output = session.send_command(
                    "configure verify plat",
                    expect="# ", timeout=60,
                )
                if "sg-sfs-scanner" in output and "Running" in output:
                    logger.info("Scanner pod is running")
                    return
                logger.info("Scanner pod not ready yet: %s", output[-300:])
        except Exception:
            logger.debug("Scanner pod check failed", exc_info=True)
        time.sleep(interval)
    raise TimeoutError("Scanner pod not running after %d attempts" % max_attempts)


def _wait_for_admin_ready(host, private_key, port=22, max_attempts=12, interval=15):
    """Poll until admin commands are accepted (no 'Try again later' errors)."""
    for attempt in range(max_attempts):
        logger.info("Checking admin readiness (attempt %d/%d)", attempt + 1, max_attempts)
        try:
            with ClishSession(host, "admin", private_key, port=port) as session:
                session.connect(timeout=30)
                output = session.send_command("enable", expect="# ", timeout=15)
                if "Try again later" not in output:
                    logger.info("Admin commands ready")
                    return
        except Exception:
            logger.debug("Admin readiness check failed", exc_info=True)
        time.sleep(interval)
    raise TimeoutError("Admin commands not ready after all attempts")


# ── Watchdog ─────────────────────────────────────────────────────────

def _describe_sg_instances(region):
    """Describe running SG instances with full metadata."""
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
                "ip": inst.get("PrivateIpAddress", ""),
                "hostname": tags.get("Name", inst["InstanceId"]),
                "provisioned": tags.get("appliance-v1fs:provisioned", "false"),
            })
    instances.sort(key=lambda x: x["hostname"])
    return instances


def _check_sg(instance_info, endpoint_id, private_key, rsa_key, pubkey_b64,
              cert_secret_name, ssm, region):
    """Run all watchdog checks on a single SG. Returns enriched result dict."""
    instance_id = instance_info["instance_id"]
    result = {
        "instance_id": instance_id,
        "hostname": instance_info["hostname"],
        "ip": instance_info["ip"],
        "provisioned": instance_info["provisioned"],
        "scanner_running": False,
        "version": "",
        "replicas_ready": None,
        "replicas_desired": None,
        "nginx_body_size": "",
        "action": "error",
    }

    param_name = f"{VERSION_PARAM_PREFIX}{instance_id}"
    try:
        stored = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        stored = ""

    with EICETunnel(instance_id, endpoint_id, remote_port=22) as tunnel:
        host = "127.0.0.1"
        port = tunnel.local_port

        with ClishSession(host, "admin", private_key, port=port) as session:
            session.connect(timeout=30)
            session.send_command("enable", expect="# ", timeout=15)
            plat_output = session.send_command(
                "configure verify plat", expect="# ", timeout=60,
            )

        scanner_running = "sg-sfs-scanner" in plat_output and "Running" in plat_output
        result["scanner_running"] = scanner_running

        if not scanner_running:
            result["action"] = "waiting"
            return result, stored, False

        client = _get_sgowner_session(tunnel, private_key, rsa_key, pubkey_b64)
        try:
            _patch_nginx_body_size(client)
            result["version"] = _get_scanner_version(client)
            ready, desired = _get_replica_count(client)
            result["replicas_ready"] = ready
            result["replicas_desired"] = desired
            result["nginx_body_size"] = _get_nginx_body_size(client)

            cert_updated = False
            if result["version"] != stored:
                logger.info("Watchdog: version changed on %s: %s -> %s",
                            instance_id, stored or "(none)", result["version"])
                cert_pem = _extract_cert(client)
                if cert_pem:
                    _store_cert(cert_secret_name, cert_pem, region)
                    cert_updated = True
                ssm.put_parameter(
                    Name=param_name, Value=result["version"],
                    Type="String", Overwrite=True,
                )
                result["action"] = "updated"
            else:
                result["action"] = "unchanged"
        finally:
            client.close()

    return result, stored, cert_updated


def _store_dashboard_state(ssm, sg_results, region):
    """Store enriched watchdog results in SSM for the dashboard widget."""
    state = {
        "checked_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "expected_nginx": f"{os.environ.get('MAX_FILE_SIZE_MB', '500')}m",
        "expected_replicas": EXPECTED_REPLICAS,
        "gateways": sg_results,
    }
    ssm.put_parameter(
        Name=DASHBOARD_STATE_PARAM,
        Value=json.dumps(state),
        Type="String",
        Overwrite=True,
    )
    logger.info("Dashboard state stored (%d gateways)", len(sg_results))


def _handle_watchdog(event, context):
    """Periodic check: verify scanner versions and re-extract cert if changed.

    Invoked by EventBridge on a schedule.
    """
    region = event.get("region", os.environ.get("AWS_REGION_NAME", "us-east-1"))
    endpoint_id = os.environ.get("EICE_ENDPOINT_ID", "")
    key_pair_id = os.environ.get("KEY_PAIR_ID", "")
    cert_secret_name = os.environ.get("CERT_SECRET_NAME", "appliance-v1fs/sg-ca-cert")

    sg_instances = _describe_sg_instances(region)
    if not sg_instances or not endpoint_id or not key_pair_id:
        logger.warning("Watchdog: missing configuration (found %d SGs), skipping",
                        len(sg_instances))
        return {"status": "skipped", "reason": "missing config"}

    private_key = _get_ssh_key(key_pair_id, region)
    ssm = boto3.client("ssm", region_name=region)

    rsa_key = paramiko.RSAKey.generate(4096)
    pubkey_b64 = rsa_key.get_base64()

    results = []
    sg_results = []

    for inst_info in sg_instances:
        instance_id = inst_info["instance_id"]
        logger.info("Watchdog: checking %s", instance_id)
        try:
            result, stored, cert_updated = _check_sg(
                inst_info, endpoint_id, private_key, rsa_key, pubkey_b64,
                cert_secret_name, ssm, region,
            )
            sg_results.append(result)

            # Preserve original return format for EventBridge compatibility
            if result["action"] == "updated":
                results.append({
                    "instance": instance_id, "action": "updated",
                    "oldVersion": stored, "newVersion": result["version"],
                    "certUpdated": cert_updated,
                })
            else:
                results.append({"instance": instance_id, "action": result["action"]})
        except Exception:
            logger.exception("Watchdog: failed checking %s", instance_id)
            results.append({"instance": instance_id, "action": "error"})
            sg_results.append({
                "instance_id": instance_id,
                "hostname": inst_info["hostname"],
                "ip": inst_info["ip"],
                "provisioned": inst_info["provisioned"],
                "scanner_running": False,
                "version": "", "replicas_ready": None, "replicas_desired": None,
                "nginx_body_size": "", "action": "error",
            })

    _store_dashboard_state(ssm, sg_results, region)
    return {"status": "complete", "results": results}


# ── CloudWatch Custom Widget (Dashboard) ──────────────────────────────

def _handle_dashboard(event, context):
    """CloudWatch custom widget handler. Returns HTML for the SG health dashboard."""
    region = os.environ.get("AWS_REGION_NAME", "us-east-1")
    ssm = boto3.client("ssm", region_name=region)

    # Handle form actions (fix buttons)
    forms = event.get("widgetContext", {}).get("forms", {}).get("all", {})
    action = forms.get("action", "")

    if action == "check_now":
        _handle_watchdog({"action": "watchdog", "region": region}, context)
    elif action in ("fix_nginx", "scale_replicas", "extract_cert"):
        _handle_fix_action(action, forms, ssm, region)

    # Read stored state
    try:
        resp = ssm.get_parameter(Name=DASHBOARD_STATE_PARAM)
        state = json.loads(resp["Parameter"]["Value"])
    except (ssm.exceptions.ParameterNotFound, KeyError):
        state = None

    return _render_dashboard_html(state)


def _handle_fix_action(action, forms, ssm, region):
    """Perform a fix action on a single SG, then update stored state."""
    instance_id = forms.get("instance_id", "")
    if not instance_id:
        return

    endpoint_id = os.environ.get("EICE_ENDPOINT_ID", "")
    key_pair_id = os.environ.get("KEY_PAIR_ID", "")
    cert_secret_name = os.environ.get("CERT_SECRET_NAME", "appliance-v1fs/sg-ca-cert")
    private_key = _get_ssh_key(key_pair_id, region)
    rsa_key = paramiko.RSAKey.generate(4096)
    pubkey_b64 = rsa_key.get_base64()

    logger.info("Dashboard fix action: %s on %s", action, instance_id)

    try:
        with EICETunnel(instance_id, endpoint_id, remote_port=22) as tunnel:
            client = _get_sgowner_session(tunnel, private_key, rsa_key, pubkey_b64)
            try:
                if action == "fix_nginx":
                    _patch_nginx_body_size(client)
                elif action == "scale_replicas":
                    _scale_replicas(client, EXPECTED_REPLICAS)
                elif action == "extract_cert":
                    cert_pem = _extract_cert(client)
                    if cert_pem:
                        _store_cert(cert_secret_name, cert_pem, region)

                # Update this SG's state in the stored dashboard data
                nginx_val = _get_nginx_body_size(client)
                ready, desired = _get_replica_count(client)
                version = _get_scanner_version(client)
            finally:
                client.close()

        # Merge updated fields into stored state
        try:
            resp = ssm.get_parameter(Name=DASHBOARD_STATE_PARAM)
            state = json.loads(resp["Parameter"]["Value"])
            for gw in state.get("gateways", []):
                if gw["instance_id"] == instance_id:
                    gw["nginx_body_size"] = nginx_val
                    gw["replicas_ready"] = ready
                    gw["replicas_desired"] = desired
                    gw["version"] = version
                    gw["action"] = "fixed"
                    break
            state["checked_at"] = datetime.datetime.now(
                datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            ssm.put_parameter(
                Name=DASHBOARD_STATE_PARAM,
                Value=json.dumps(state),
                Type="String",
                Overwrite=True,
            )
        except ssm.exceptions.ParameterNotFound:
            pass

    except Exception:
        logger.exception("Dashboard fix action failed: %s on %s", action, instance_id)


def _render_dashboard_html(state):
    """Render the SG health dashboard as HTML for a CloudWatch custom widget."""
    if not state:
        return (
            '<div style="padding:16px;font-family:Amazon Ember,Arial,sans-serif">'
            "<p>No data yet. The watchdog runs every 15 minutes, or click below to check now.</p>"
            '<form><input type="hidden" name="action" value="check_now">'
            '<button class="btn btn-primary">Check Now</button></form></div>'
        )

    checked_at = state.get("checked_at", "unknown")
    expected_nginx = state.get("expected_nginx", "500m")
    expected_replicas = state.get("expected_replicas", EXPECTED_REPLICAS)
    gateways = state.get("gateways", [])

    healthy = sum(1 for g in gateways if g.get("scanner_running"))
    total = len(gateways)

    css = (
        "<style>"
        "table{border-collapse:collapse;width:100%;font-family:Amazon Ember,Arial,sans-serif;font-size:13px}"
        "th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #e0e0e0}"
        "th{background:#fafafa;font-weight:600;color:#545b64}"
        "tr:hover{background:#f5f8fa}"
        ".ok{color:#1d8102;font-weight:600}"
        ".warn{color:#ff9900;font-weight:600}"
        ".err{color:#d13212;font-weight:600}"
        ".mono{font-family:Monaco,Menlo,monospace;font-size:12px}"
        ".hdr{display:flex;justify-content:space-between;align-items:center;"
        "padding:0 0 12px 0;font-family:Amazon Ember,Arial,sans-serif}"
        ".hdr-left{font-size:14px;color:#545b64}"
        "button.btn{margin:0 2px}"
        "</style>"
    )

    header = (
        '<div class="hdr">'
        f'<span class="hdr-left">'
        f"<strong>{healthy}/{total}</strong> gateways healthy &nbsp; | &nbsp; "
        f"Last checked: <strong>{checked_at}</strong>"
        "</span>"
        '<form style="margin:0"><input type="hidden" name="action" value="check_now">'
        '<button class="btn btn-primary">Check Now</button></form>'
        "</div>"
    )

    rows = []
    for gw in gateways:
        instance_id = gw.get("instance_id", "")
        hostname = gw.get("hostname", "")
        ip = gw.get("ip", "")
        running = gw.get("scanner_running", False)
        version = gw.get("version", "") or "-"
        ready = gw.get("replicas_ready")
        desired = gw.get("replicas_desired")
        nginx = gw.get("nginx_body_size", "") or "-"
        action_taken = gw.get("action", "")

        # Scanner status
        if action_taken == "error":
            status_html = '<span class="err">ERROR</span>'
        elif running:
            status_html = '<span class="ok">Running</span>'
        else:
            status_html = '<span class="err">Not Running</span>'

        # Replicas
        if ready is not None and desired is not None:
            replica_str = f"{ready}/{desired}"
            if ready >= expected_replicas:
                replica_html = f'<span class="ok">{replica_str}</span>'
            else:
                replica_html = (
                    f'<span class="warn">{replica_str}</span> '
                    f'<form style="display:inline;margin:0">'
                    f'<input type="hidden" name="action" value="scale_replicas">'
                    f'<input type="hidden" name="instance_id" value="{instance_id}">'
                    f'<button class="btn btn-sm">Scale to {expected_replicas}</button>'
                    f"</form>"
                )
        else:
            replica_html = '<span class="err">-</span>'

        # nginx
        if nginx == expected_nginx:
            nginx_html = f'<span class="ok">{nginx}</span>'
        elif nginx == "-":
            nginx_html = '<span class="err">-</span>'
        else:
            nginx_html = (
                f'<span class="warn">{nginx}</span> '
                f'<form style="display:inline;margin:0">'
                f'<input type="hidden" name="action" value="fix_nginx">'
                f'<input type="hidden" name="instance_id" value="{instance_id}">'
                f'<button class="btn btn-sm">Fix</button>'
                f"</form>"
            )

        # Cert action
        cert_html = (
            f'<form style="display:inline;margin:0">'
            f'<input type="hidden" name="action" value="extract_cert">'
            f'<input type="hidden" name="instance_id" value="{instance_id}">'
            f'<button class="btn btn-sm">Re-extract</button>'
            f"</form>"
        )

        # Truncate version to last segment for readability
        version_short = version.rsplit("/", 1)[-1] if "/" in version else version

        rows.append(
            f"<tr>"
            f'<td><strong>{hostname}</strong><br>'
            f'<span class="mono" style="font-size:11px;color:#879596">{instance_id}</span></td>'
            f'<td class="mono">{ip}</td>'
            f"<td>{status_html}</td>"
            f'<td class="mono">{version_short}</td>'
            f"<td>{replica_html}</td>"
            f"<td>{nginx_html}</td>"
            f"<td>{cert_html}</td>"
            f"</tr>"
        )

    table = (
        "<table>"
        "<thead><tr>"
        "<th>Gateway</th><th>IP</th><th>Scanner</th>"
        "<th>Version</th><th>Replicas</th>"
        f"<th>nginx body-size<br>(expect {expected_nginx})</th>"
        "<th>CA Cert</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )

    return css + header + table

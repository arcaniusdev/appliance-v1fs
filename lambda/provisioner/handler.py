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


def handler(event, context):
    """ASG lifecycle hook handler + watchdog.

    Dispatches on detail-type (EventBridge ASG lifecycle event):
      - EC2 Instance-Launch Lifecycle Action: Provision a new SG
      - EC2 Instance-Terminate Lifecycle Action: Cleanup on terminate

    Or on action key (EventBridge / direct invoke):
      - watchdog: Check SG versions, re-extract cert if changed
    """
    # ASG lifecycle event via SNS notification
    if "Records" in event and event["Records"][0].get("EventSource") == "aws:sns":
        return _handle_sns_lifecycle(event, context)

    # ASG lifecycle event (direct invoke or EventBridge)
    detail_type = event.get("detail-type", "")
    if detail_type in (
        "EC2 Instance-Launch Lifecycle Action",
        "EC2 Instance-Terminate Lifecycle Action",
    ):
        return _handle_lifecycle(event, context)

    # Direct invoke (watchdog from EventBridge)
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


# ── SNS Lifecycle Unwrapper ───────────────────────────────────────────

def _handle_sns_lifecycle(event, context):
    """Unwrap SNS lifecycle notification and delegate to _handle_lifecycle."""
    message = json.loads(event["Records"][0]["Sns"]["Message"])
    # SNS lifecycle message has: LifecycleHookName, AccountId, RequestId,
    # LifecycleTransition, AutoScalingGroupName, EC2InstanceId, LifecycleActionToken
    transition = message.get("LifecycleTransition", "")
    if "LAUNCHING" in transition:
        detail_type = "EC2 Instance-Launch Lifecycle Action"
    elif "TERMINATING" in transition:
        detail_type = "EC2 Instance-Terminate Lifecycle Action"
    else:
        logger.warning("Unknown lifecycle transition: %s", transition)
        return {"status": "skipped", "reason": f"unknown transition: {transition}"}

    # Convert to the same event format _handle_lifecycle expects
    lifecycle_event = {
        "detail-type": detail_type,
        "region": event["Records"][0].get("EventSubscriptionArn", "").split(":")[3] or "us-east-1",
        "detail": {
            "LifecycleHookName": message["LifecycleHookName"],
            "AutoScalingGroupName": message["AutoScalingGroupName"],
            "LifecycleActionToken": message.get("LifecycleActionToken", ""),
            "EC2InstanceId": message["EC2InstanceId"],
            "LifecycleTransition": transition,
        },
    }
    return _handle_lifecycle(lifecycle_event, context)


# ── Dynamic SG Discovery ─────────────────────────────────────────────

def _discover_sg_instances(region):
    """Discover running SG instance IDs via EC2 tags."""
    tag_key = os.environ.get("SG_TAG_KEY", "appliance-v1fs:stack")
    tag_value = os.environ.get("SG_TAG_VALUE", "")
    if not tag_value:
        return []

    ec2 = boto3.client("ec2", region_name=region)
    resp = ec2.describe_instances(Filters=[
        {"Name": f"tag:{tag_key}", "Values": [tag_value]},
        {"Name": "instance-state-name", "Values": ["running"]},
    ])
    return [
        inst["InstanceId"]
        for res in resp["Reservations"]
        for inst in res["Instances"]
    ]


def _assign_hostname(instance_id, region):
    """Assign a unique hostname to a new SG using atomic SSM claims."""
    prefix = os.environ.get("HOSTNAME_PREFIX", "FSVA-AWS")
    ssm = boto3.client("ssm", region_name=region)

    # Try to atomically claim a hostname number using PutParameter with Overwrite=False
    for num in range(1, 100):
        hostname = f"{prefix}-{num:02d}"
        claim_param = f"/appliance-v1fs/hostname-claim/{num:02d}"
        try:
            ssm.put_parameter(
                Name=claim_param,
                Value=instance_id,
                Type="String",
                Overwrite=False,  # fails if already exists — atomic claim
            )
            # Claimed successfully — also store reverse mapping for cleanup
            ssm.put_parameter(
                Name=f"/appliance-v1fs/hostname/{instance_id}",
                Value=hostname,
                Type="String",
                Overwrite=True,
            )
            logger.info("Assigned hostname %s to %s", hostname, instance_id)
            return hostname
        except ssm.exceptions.ParameterAlreadyExists:
            continue  # number already claimed, try next

    raise RuntimeError("No available hostname numbers (1-99 exhausted)")


def _release_hostname(instance_id, region):
    """Release hostname assignment for a terminated SG."""
    ssm = boto3.client("ssm", region_name=region)
    try:
        resp = ssm.get_parameter(Name=f"/appliance-v1fs/hostname/{instance_id}")
        hostname = resp["Parameter"]["Value"]
        # Extract number from hostname (e.g., "FSVA-AWS-01" → "01")
        num = hostname.rsplit("-", 1)[-1]
        ssm.delete_parameter(Name=f"/appliance-v1fs/hostname-claim/{num}")
        ssm.delete_parameter(Name=f"/appliance-v1fs/hostname/{instance_id}")
        logger.info("Released hostname %s for %s", hostname, instance_id)
    except ssm.exceptions.ParameterNotFound:
        logger.debug("No hostname param found for %s", instance_id)
    except Exception:
        logger.warning("Failed to release hostname for %s", instance_id, exc_info=True)


# ── ASG Lifecycle Hook ───────────────────────────────────────────────

def _handle_lifecycle(event, context):
    """Handle ASG lifecycle events: provision on launch, cleanup on terminate."""
    detail = event["detail"]
    instance_id = detail["EC2InstanceId"]
    hook_name = detail["LifecycleHookName"]
    asg_name = detail["AutoScalingGroupName"]
    action_token = detail.get("LifecycleActionToken") or ""
    detail_type = event["detail-type"]
    region = event.get("region", os.environ.get("AWS_REGION_NAME", "us-east-1"))

    asg_client = boto3.client("autoscaling", region_name=region)

    def _complete_lifecycle(result):
        kwargs = dict(
            LifecycleHookName=hook_name,
            AutoScalingGroupName=asg_name,
            LifecycleActionResult=result,
        )
        if action_token:
            kwargs["LifecycleActionToken"] = action_token
        else:
            kwargs["InstanceId"] = instance_id
        asg_client.complete_lifecycle_action(**kwargs)

    if detail_type == "EC2 Instance-Terminate Lifecycle Action":
        logger.info("Lifecycle TERMINATE: %s — releasing hostname", instance_id)
        _release_hostname(instance_id, region)
        # Clean up version SSM param
        ssm = boto3.client("ssm", region_name=region)
        try:
            ssm.delete_parameter(Name=f"{VERSION_PARAM_PREFIX}{instance_id}")
        except Exception:
            pass
        _complete_lifecycle("CONTINUE")
        return {"status": "terminated", "instance": instance_id}

    # Launch lifecycle — full provisioning flow
    logger.info("Lifecycle LAUNCH: %s — starting provisioning", instance_id)
    endpoint_id = os.environ.get("EICE_ENDPOINT_ID", "")
    key_pair_id = os.environ.get("KEY_PAIR_ID", "")
    cert_secret_name = os.environ.get("CERT_SECRET_NAME", "appliance-v1fs/sg-ca-cert")

    try:
        # Get registration token from Secrets Manager
        sm = boto3.client("secretsmanager", region_name=region)
        token_secret = os.environ.get("REGISTRATION_TOKEN_SECRET", "appliance-v1fs/sg-registration-token")
        token = sm.get_secret_value(SecretId=token_secret)["SecretString"]

        private_key = _get_ssh_key(key_pair_id, region)
        hostname = _assign_hostname(instance_id, region)

        # Tag instance with its Vision One hostname
        ec2 = boto3.client("ec2", region_name=region)
        ec2.create_tags(Resources=[instance_id], Tags=[
            {"Key": "Name", "Value": hostname},
        ])
        logger.info("Tagged %s as %s", instance_id, hostname)

        # Register the SG — retry if "Try again later" (SG registration subsystem still booting)
        with EICETunnel(instance_id, endpoint_id, remote_port=22) as tunnel:
            host = "127.0.0.1"
            port = tunnel.local_port

            _wait_for_admin_ready(host, private_key, port=port)

            logger.info("Setting hostname to %s", hostname)
            with ClishSession(host, "admin", private_key, port=port) as session:
                session.connect(timeout=30)
                session.send_command("enable", expect="# ", timeout=15)
                session.send_command(
                    f"configure endpoint {hostname}",
                    expect="# ", timeout=30,
                )

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

        # Verify registration — retry banner check up to 5 times (registration can take 30-60s)
        banner = ""
        for verify_attempt in range(5):
            time.sleep(30)
            logger.info("Verifying registration via banner (attempt %d/5)", verify_attempt + 1)
            with EICETunnel(instance_id, endpoint_id, remote_port=22) as vtunnel:
                with ClishSession("127.0.0.1", "admin", private_key, port=vtunnel.local_port) as session:
                    banner = session.connect(timeout=30)
            if "Status: Registered" in banner:
                break

        if "Status: Registered" not in banner:
            raise RuntimeError(f"Registration verification failed after retries. Banner: {banner[-500:]}")

        logger.info("Service Gateway %s registered as %s", instance_id, hostname)

        # Wait for scanner pod + extract cert
        _lifecycle_wait_for_scanner(
            instance_id, endpoint_id, private_key, cert_secret_name, region,
        )

        _complete_lifecycle("CONTINUE")
        logger.info("Lifecycle LAUNCH complete: %s", instance_id)
        return {"status": "provisioned", "instance": instance_id, "hostname": hostname}

    except Exception as e:
        logger.exception("Lifecycle provisioning failed for %s: %s", instance_id, e)
        _complete_lifecycle("ABANDON")
        return {"status": "failed", "instance": instance_id, "error": str(e)}


def _lifecycle_wait_for_scanner(instance_id, endpoint_id, private_key, cert_secret_name, region):
    """Poll for File Security scanner pod and extract cert (lifecycle version)."""
    for attempt in range(60):  # up to ~30 minutes
        logger.info("Waiting for scanner pod on %s (attempt %d)", instance_id, attempt + 1)
        try:
            with EICETunnel(instance_id, endpoint_id, remote_port=22) as tunnel:
                with ClishSession("127.0.0.1", "admin", private_key, port=tunnel.local_port) as session:
                    session.connect(timeout=30)
                    session.send_command("enable", expect="# ", timeout=15)
                    output = session.send_command(
                        "configure verify plat",
                        expect="# ", timeout=60,
                    )

            if "sg-sfs-scanner" in output and "Running" in output:
                logger.info("File Security scanner pod detected on %s", instance_id)
                break
        except Exception:
            logger.warning("SSH check failed on %s (attempt %d)", instance_id, attempt, exc_info=True)
        time.sleep(30)
    else:
        raise TimeoutError(f"File Security scanner not detected on {instance_id}")

    # Extract cert and store version
    rsa_key = paramiko.RSAKey.generate(4096)
    pubkey_b64 = rsa_key.get_base64()

    cert_pem = None
    for cert_attempt in range(5):
        try:
            with EICETunnel(instance_id, endpoint_id, remote_port=22) as tunnel:
                client = _get_sgowner_session(tunnel, private_key, rsa_key, pubkey_b64)
                cert_pem = _extract_cert(client)
                version = _get_scanner_version(client)
                logger.info("Scanner version on %s: %s", instance_id, version)
                client.close()

            if cert_pem:
                logger.info("CA cert extracted from %s (%d bytes)", instance_id, len(cert_pem))
                break
        except Exception:
            logger.warning("Cert extraction attempt %d failed on %s", cert_attempt + 1, instance_id, exc_info=True)
        time.sleep(10)

    if cert_pem is None:
        raise ConnectionError(f"Failed to extract CA cert from {instance_id}")

    _store_cert(cert_secret_name, cert_pem, region)

    if version:
        ssm = boto3.client("ssm", region_name=region)
        ssm.put_parameter(
            Name=f"{VERSION_PARAM_PREFIX}{instance_id}",
            Value=version,
            Type="String",
            Overwrite=True,
        )


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

def _handle_watchdog(event, context):
    """Periodic check: verify scanner versions, re-extract cert if changed.

    Invoked by EventBridge on a schedule. Checks each SG for version changes
    and re-applies customizations as needed.
    """
    region = event.get("region", os.environ.get("AWS_REGION", "us-east-1"))
    sg_instances = _discover_sg_instances(region)
    endpoint_id = os.environ.get("EICE_ENDPOINT_ID", "")
    key_pair_id = os.environ.get("KEY_PAIR_ID", "")
    cert_secret_name = os.environ.get("CERT_SECRET_NAME", "appliance-v1fs/sg-ca-cert")

    if not sg_instances or not endpoint_id or not key_pair_id:
        logger.warning("Watchdog: missing configuration (found %d SGs), skipping", len(sg_instances))
        return {"status": "skipped", "reason": "missing config"}

    private_key = _get_ssh_key(key_pair_id, region)
    ssm = boto3.client("ssm", region_name=region)

    rsa_key = paramiko.RSAKey.generate(4096)
    pubkey_b64 = rsa_key.get_base64()

    results = []
    cert_updated = False

    for instance_id in sg_instances:
        logger.info("Watchdog: checking %s", instance_id)
        try:
            with EICETunnel(instance_id, endpoint_id, remote_port=22) as tunnel:
                client = _get_sgowner_session(tunnel, private_key, rsa_key, pubkey_b64)
                current_version = _get_scanner_version(client)

                # Get stored version
                param_name = f"{VERSION_PARAM_PREFIX}{instance_id}"
                try:
                    stored = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
                except ssm.exceptions.ParameterNotFound:
                    stored = ""

                if current_version != stored:
                    logger.warning(
                        "Watchdog: version changed on %s: %s -> %s",
                        instance_id, stored, current_version,
                    )

                    # Re-extract CA cert
                    cert_pem = _extract_cert(client)
                    if cert_pem:
                        _store_cert(cert_secret_name, cert_pem, region)
                        cert_updated = True
                        logger.info("Watchdog: CA cert re-extracted from %s", instance_id)

                    # Update stored version
                    ssm.put_parameter(
                        Name=param_name,
                        Value=current_version,
                        Type="String",
                        Overwrite=True,
                    )

                    results.append({
                        "instance": instance_id,
                        "action": "updated",
                        "oldVersion": stored,
                        "newVersion": current_version,
                        "certUpdated": cert_updated,
                    })
                else:
                    logger.info("Watchdog: %s unchanged (%s)", instance_id, current_version)
                    results.append({"instance": instance_id, "action": "unchanged"})

                client.close()
        except Exception:
            logger.exception("Watchdog: failed checking %s", instance_id)
            results.append({"instance": instance_id, "action": "error"})

    return {"status": "complete", "results": results}



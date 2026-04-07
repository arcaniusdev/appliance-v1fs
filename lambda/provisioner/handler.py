import json
import logging
import os
import re
import time

import boto3
import paramiko

from ssh_helper import ClishSession
from eice_tunnel import EICETunnel

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# SSM parameter for tracking scanner version per SG
VERSION_PARAM_PREFIX = "/appliance-v1fs/scanner-version/"
EXPECTED_REPLICAS = 1
_SAFE_HOSTNAME = re.compile(r'^[A-Za-z0-9\-]{1,63}$')


def _validate_hostname(hostname):
    """Validate hostname contains only safe characters."""
    if not _SAFE_HOSTNAME.match(hostname):
        raise ValueError(f"Invalid hostname: {hostname!r}")
    return hostname


def _sync_dns_records(region):
    """Sync Route 53 A records with running SG IPs."""
    zone_id = os.environ.get("SG_DNS_ZONE_ID", "")
    dns_name = os.environ.get("SG_DNS_NAME", "")
    if not zone_id or not dns_name:
        return

    all_sgs = _discover_sg_instances(region)
    ips = []
    ec2 = boto3.client("ec2", region_name=region)
    for sg in all_sgs:
        resp = ec2.describe_instances(InstanceIds=[sg["instance_id"]])
        for res in resp["Reservations"]:
            for inst in res["Instances"]:
                if inst.get("PrivateIpAddress"):
                    ips.append(inst["PrivateIpAddress"])

    if not ips:
        logger.warning("DNS sync: no running SG IPs found, skipping")
        return

    try:
        r53 = boto3.client("route53")
        records = [{"Value": ip} for ip in sorted(set(ips))]
        r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [{
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": dns_name,
                        "Type": "A",
                        "TTL": 10,
                        "ResourceRecords": records,
                    },
                }],
            },
        )
        logger.info("DNS synced: %s → %s", dns_name, [r["Value"] for r in records])
    except Exception:
        logger.warning("DNS sync failed", exc_info=True)


def handler(event, context):
    """Service Gateway provisioner (watchdog-only).

    Invoked on a 15-minute schedule. Discovers SG instances by tag,
    provisions any that are unprovisioned, checks scanner versions,
    re-applies customizations, and syncs DNS.
    """
    return _handle_watchdog(event, context)


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

def _discover_sg_instances(region):
    """Discover running SG instances with metadata."""
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

def _handle_watchdog(event, context):
    """Periodic provisioner — handles the full SG lifecycle.

    Invoked by EventBridge on a 15-minute schedule. For each SG instance:
    1. Not registered → set hostname, register with Vision One, tag
    2. Registered but no scanner pod → wait (FS must be installed via V1 console)
    3. Scanner pod running but not provisioned → extract cert, patch nginx, tag
    4. Already provisioned → check scanner version, re-extract cert if changed
    Also syncs DNS A records with running SG IPs after each run.
    """
    region = event.get("region", os.environ.get("AWS_REGION_NAME", "us-east-1"))
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

    for inst_info in sg_instances:
        instance_id = inst_info["instance_id"]
        logger.info("Watchdog: checking %s (%s)", instance_id, inst_info["hostname"])
        try:
            # Get stored version
            param_name = f"{VERSION_PARAM_PREFIX}{instance_id}"
            try:
                stored = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
            except ssm.exceptions.ParameterNotFound:
                stored = ""

            # Single tunnel per SG for all checks
            with EICETunnel(instance_id, endpoint_id, remote_port=22) as tunnel:
                host = "127.0.0.1"
                port = tunnel.local_port

                # Register with Vision One if not yet registered
                if inst_info["registered"] != "true":
                    logger.info("Watchdog: %s not registered, checking status", instance_id)
                    try:
                        with ClishSession(host, "admin", private_key, port=port) as session:
                            banner = session.connect(timeout=30)

                        if "Status: Registered" in banner:
                            logger.info("Watchdog: %s already registered (banner)", instance_id)
                        else:
                            # Set hostname via sgowner
                            hostname = _validate_hostname(inst_info["hostname"])
                            logger.info("Watchdog: setting hostname to %s", hostname)
                            temp_rsa = paramiko.RSAKey.generate(4096)
                            temp_pub = temp_rsa.get_base64()
                            sgowner = _get_sgowner_session(tunnel, private_key, temp_rsa, temp_pub)
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

                            # Register
                            sm_client = boto3.client("secretsmanager", region_name=region)
                            token_secret = os.environ.get("REGISTRATION_TOKEN_SECRET", "appliance-v1fs/sg-registration-token")
                            token = sm_client.get_secret_value(SecretId=token_secret)["SecretString"]

                            reg_output = ""
                            for reg_attempt in range(3):
                                logger.info("Watchdog: registering %s (attempt %d/3)", instance_id, reg_attempt + 1)
                                with ClishSession(host, "admin", private_key, port=port) as session:
                                    session.connect(timeout=30)
                                    session.send_command("enable", expect="# ", timeout=15)
                                    reg_output = session.send_command(
                                        f"register {token}",
                                        expect="# ", timeout=300,
                                    )
                                    logger.info("Watchdog: register complete (output length: %d)", len(reg_output))
                                if "Try again later" not in reg_output:
                                    break
                                logger.warning("Watchdog: register blocked, retrying in 30s")
                                time.sleep(30)

                            # Verify registration
                            time.sleep(30)
                            with ClishSession(host, "admin", private_key, port=port) as session:
                                banner = session.connect(timeout=30)
                            if "Status: Registered" not in banner:
                                logger.warning("Watchdog: %s registration not confirmed yet", instance_id)
                                results.append({"instance": instance_id, "action": "registering"})
                                continue

                            logger.info("Watchdog: %s registered successfully", instance_id)

                        # Tag as registered
                        ec2 = boto3.client("ec2", region_name=region)
                        ec2.create_tags(Resources=[instance_id], Tags=[
                            {"Key": "appliance-v1fs:registered", "Value": "true"},
                        ])
                    except Exception:
                        logger.warning("Watchdog: registration failed for %s", instance_id, exc_info=True)
                        results.append({"instance": instance_id, "action": "registration_failed"})
                        continue

                # Check if scanner pod is running via admin clish
                with ClishSession(host, "admin", private_key, port=port) as session:
                    session.connect(timeout=30)
                    session.send_command("enable", expect="# ", timeout=15)
                    plat_output = session.send_command(
                        "configure verify plat",
                        expect="# ", timeout=60,
                    )

                scanner_running = "sg-sfs-scanner" in plat_output and "Running" in plat_output

                if not scanner_running:
                    logger.info("Watchdog: %s — scanner pod not running yet", instance_id)
                    results.append({"instance": instance_id, "action": "waiting"})
                    continue

                # Get version, cert, re-apply nginx patch, and scale replicas via sgowner
                client = _get_sgowner_session(tunnel, private_key, rsa_key, pubkey_b64)
                _patch_nginx_body_size(client)
                current_version = _get_scanner_version(client)

                # Complete provisioning for SGs that have the scanner pod but
                # were never fully provisioned (e.g., File Security was installed
                # manually via the Vision One console after the provisioner timed out)
                if inst_info["provisioned"] != "true":
                    logger.info("Watchdog: completing provisioning for %s (%s)",
                                instance_id, inst_info["hostname"])
                    _scale_replicas(client, EXPECTED_REPLICAS)
                    cert_pem = _extract_cert(client)
                    if cert_pem:
                        _store_cert(cert_secret_name, cert_pem, region)
                        cert_updated = True
                    ssm.put_parameter(
                        Name=param_name, Value=current_version,
                        Type="String", Overwrite=True,
                    )
                    ec2 = boto3.client("ec2", region_name=region)
                    ec2.create_tags(Resources=[instance_id], Tags=[
                        {"Key": "appliance-v1fs:provisioned", "Value": "true"},
                    ])
                    results.append({"instance": instance_id, "action": "provisioned"})
                    logger.info("Watchdog: %s (%s) now fully provisioned",
                                instance_id, inst_info["hostname"])
                elif current_version != stored:
                    logger.info(
                        "Watchdog: version changed on %s: %s -> %s",
                        instance_id, stored or "(none)", current_version,
                    )

                    cert_pem = _extract_cert(client)
                    if cert_pem:
                        _store_cert(cert_secret_name, cert_pem, region)
                        cert_updated = True
                        logger.info("Watchdog: CA cert extracted from %s", instance_id)

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

    # Sync DNS with running SGs
    _sync_dns_records(region)

    return {"status": "complete", "results": results}

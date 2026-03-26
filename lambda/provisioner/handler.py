import json
import logging
import os
import time

import boto3

import cfn_response
from ssh_helper import ClishSession
from cert_extractor import extract_cert_pem
from eice_tunnel import EICETunnel

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    """CloudFormation custom resource handler.

    Dispatches on ResourceProperties.Action:
      - register: Register Service Gateway with Vision One
      - wait-for-scanner: Poll for File Security pod, extract cert, store in SM
    """
    request_type = event.get("RequestType", "")
    if request_type == "Delete":
        cfn_response.send(event, context, "SUCCESS")
        return

    try:
        action = event["ResourceProperties"]["Action"]
        if action == "register":
            data = _handle_register(event, context)
        elif action == "wait-for-scanner":
            data = _handle_wait_for_scanner(event, context)
        else:
            raise ValueError(f"Unknown action: {action}")
        cfn_response.send(event, context, "SUCCESS", data=data)
    except Exception as e:
        logger.exception("Custom resource failed: %s", e)
        cfn_response.send(event, context, "FAILED", reason=str(e))


def _get_ssh_key(key_pair_id: str, region: str) -> str:
    ssm = boto3.client("ssm", region_name=region)
    resp = ssm.get_parameter(
        Name=f"/ec2/keypair/{key_pair_id}",
        WithDecryption=True,
    )
    return resp["Parameter"]["Value"]


def _handle_register(event, context):
    props = event["ResourceProperties"]
    instance_id = props["InstanceId"]
    endpoint_id = props["EndpointId"]
    token = props["RegistrationToken"]
    key_pair_id = props["KeyPairId"]
    hostname = props.get("Hostname", "FSVA-AWS-01")
    region = props.get("Region", os.environ.get("AWS_REGION"))

    private_key = _get_ssh_key(key_pair_id, region)

    with EICETunnel(instance_id, endpoint_id, remote_port=22) as tunnel:
        host = "127.0.0.1"
        port = tunnel.local_port

        # Wait for appliance services to finish initializing
        _wait_for_admin_ready(host, private_key, port=port)

        # Set hostname before registration so Vision One sees the correct name
        logger.info("Setting hostname to %s", hostname)
        with ClishSession(host, "admin", private_key, port=port) as session:
            session.connect(timeout=30)
            session.send_command("enable", expect="# ", timeout=15)
            output = session.send_command(
                f"configure endpoint {hostname}",
                expect="# ",
                timeout=30,
            )
            logger.info("Hostname output: %s", output[-200:])

        # Register
        logger.info("Registering Service Gateway")
        with ClishSession(host, "admin", private_key, port=port) as session:
            session.connect(timeout=30)
            session.send_command("enable", expect="# ", timeout=15)
            output = session.send_command(
                f"register {token}",
                expect="# ",
                timeout=300,
            )
            logger.info("Register output: %s", output[-500:])

        if "Try again later" in output:
            raise RuntimeError(f"Register command blocked: {output[-300:]}")

        # Verify registration via banner
        time.sleep(15)
        logger.info("Verifying registration via banner")
        with ClishSession(host, "admin", private_key, port=port) as session:
            banner = session.connect(timeout=30)

    if "Status: Registered" not in banner:
        raise RuntimeError(
            f"Registration verification failed. Banner: {banner[-500:]}"
        )

    logger.info("Service Gateway registered as %s", hostname)
    return {"Status": "Registered", "InstanceId": instance_id, "Hostname": hostname}


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


def _handle_wait_for_scanner(event, context):
    props = event["ResourceProperties"]
    instance_id = props["InstanceId"]
    endpoint_id = props["EndpointId"]
    sg_ip = props["ServiceGatewayIP"]
    key_pair_id = props["KeyPairId"]
    region = props.get("Region", os.environ.get("AWS_REGION"))
    secret_name = props["CACertSecretName"]
    retry_state = json.loads(props.get("RetryState", "{}"))

    private_key = _get_ssh_key(key_pair_id, region)
    attempt = retry_state.get("attempt", 0)

    scanner_found = False
    while True:
        remaining_ms = context.get_remaining_time_in_millis()
        if remaining_ms < 120_000:
            logger.info(
                "Lambda timeout approaching (%dms left), re-invoking (attempt %d)",
                remaining_ms, attempt,
            )
            _reinvoke(event, context, attempt)
            return {"Status": "Re-invoked", "Attempt": attempt}

        logger.info("Checking for File Security scanner (attempt %d)", attempt + 1)
        try:
            with EICETunnel(instance_id, endpoint_id, remote_port=22) as tunnel:
                with ClishSession("127.0.0.1", "admin", private_key, port=tunnel.local_port) as session:
                    session.connect(timeout=30)
                    session.send_command("enable", expect="# ", timeout=15)
                    output = session.send_command(
                        "configure verify plat",
                        expect="# ",
                        timeout=60,
                    )

            if "sg-sfs-scanner" in output and "Running" in output:
                logger.info("File Security scanner pod detected")
                scanner_found = True
                break
        except Exception:
            logger.warning("SSH check failed (attempt %d)", attempt, exc_info=True)

        attempt += 1
        time.sleep(30)

    if not scanner_found:
        raise TimeoutError("File Security scanner not detected")

    # Extract CA cert via EICE tunnel on port 443
    cert_pem = None
    for cert_attempt in range(10):
        try:
            with EICETunnel(instance_id, endpoint_id, remote_port=443) as tunnel:
                logger.info("Extracting CA certificate (attempt %d)", cert_attempt + 1)
                cert_pem = extract_cert_pem("127.0.0.1", port=tunnel.local_port, retries=1)
                break
        except Exception:
            logger.warning("Cert extraction attempt %d failed", cert_attempt + 1, exc_info=True)
            time.sleep(10)
    if cert_pem is None:
        raise ConnectionError("Failed to extract CA cert after all attempts")

    # Store in Secrets Manager
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

    return {"Status": "Complete", "CACertSecretName": secret_name}


def _reinvoke(event, context, attempt):
    """Re-invoke this Lambda with updated retry state to extend polling."""
    lam = boto3.client("lambda")
    event_copy = json.loads(json.dumps(event))
    event_copy["ResourceProperties"]["RetryState"] = json.dumps({"attempt": attempt})
    lam.invoke(
        FunctionName=context.function_name,
        InvocationType="Event",
        Payload=json.dumps(event_copy).encode(),
    )

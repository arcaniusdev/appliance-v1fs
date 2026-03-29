import glob
import logging
import os
import socket
import subprocess
import time
import zipfile

import boto3

logger = logging.getLogger(__name__)

AWS_CLI_DIR = "/tmp/awscli"
AWS_CLI = None


def _ensure_aws_cli():
    """Download AWS CLI from S3 to /tmp on first use (cold start)."""
    global AWS_CLI
    if AWS_CLI and os.access(AWS_CLI, os.X_OK):
        return AWS_CLI

    # Check if already extracted from a previous invocation
    candidates = glob.glob(f"{AWS_CLI_DIR}/dist/aws")
    if candidates and os.access(candidates[0], os.X_OK):
        AWS_CLI = candidates[0]
        logger.info("AWS CLI already at %s", AWS_CLI)
        return AWS_CLI

    # Download from the deploy bucket
    bucket = os.environ.get("DEPLOY_BUCKET")
    if not bucket:
        raise RuntimeError("DEPLOY_BUCKET not set — cannot download AWS CLI")

    zip_path = "/tmp/awscli-runtime.zip"
    logger.info("Downloading AWS CLI from s3://%s/awscli-runtime.zip", bucket)
    s3 = boto3.client("s3")
    s3.download_file(bucket, "awscli-runtime.zip", zip_path)

    os.makedirs(AWS_CLI_DIR, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(AWS_CLI_DIR)
    os.remove(zip_path)

    # Make the binary executable
    binary = f"{AWS_CLI_DIR}/dist/aws"
    os.chmod(binary, 0o755)
    AWS_CLI = binary
    logger.info("AWS CLI extracted to %s", AWS_CLI)
    return AWS_CLI


class EICETunnel:
    """Opens a local TCP tunnel to an EC2 instance through an EC2 Instance Connect Endpoint."""

    def __init__(self, instance_id: str, endpoint_id: str, remote_port: int = 22):
        self.instance_id = instance_id
        self.endpoint_id = endpoint_id
        self.remote_port = remote_port
        self.local_port = None
        self._proc = None

    def open(self, timeout: int = 60) -> int:
        aws_cli = _ensure_aws_cli()

        # Find a free local port
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.local_port = s.getsockname()[1]

        cmd = [
            aws_cli, "ec2-instance-connect", "open-tunnel",
            "--instance-id", self.instance_id,
            "--instance-connect-endpoint-id", self.endpoint_id,
            "--remote-port", str(self.remote_port),
            "--local-port", str(self.local_port),
        ]
        logger.info("Opening EICE tunnel: %s -> %s:%d on localhost:%d",
                     self.endpoint_id, self.instance_id, self.remote_port, self.local_port)

        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Wait for tunnel to become reachable
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.local_port), timeout=2):
                    logger.info("EICE tunnel ready on localhost:%d", self.local_port)
                    return self.local_port
            except (OSError, socket.timeout):
                if self._proc.poll() is not None:
                    stderr = self._proc.stderr.read().decode()
                    raise RuntimeError(f"EICE tunnel process exited: {stderr}")
                time.sleep(1)

        self.close()
        raise TimeoutError(f"EICE tunnel not ready after {timeout}s")

    def close(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            self._proc.wait(timeout=5)
            logger.info("EICE tunnel closed")

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

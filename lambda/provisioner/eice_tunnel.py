import glob
import logging
import os
import socket
import subprocess
import time

logger = logging.getLogger(__name__)

# Lambda layers extract to /opt but don't preserve symlinks from zips.
# Find the actual AWS CLI binary in the layer's dist/ directory.
_AWS_CLI_CANDIDATES = glob.glob("/opt/aws-cli/v2/*/dist/aws")
AWS_CLI = next((p for p in _AWS_CLI_CANDIDATES if os.access(p, os.X_OK)), "aws")


class EICETunnel:
    """Opens a local TCP tunnel to an EC2 instance through an EC2 Instance Connect Endpoint."""

    def __init__(self, instance_id: str, endpoint_id: str, remote_port: int = 22):
        self.instance_id = instance_id
        self.endpoint_id = endpoint_id
        self.remote_port = remote_port
        self.local_port = None
        self._proc = None

    def open(self, timeout: int = 60) -> int:
        # Find a free local port
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.local_port = s.getsockname()[1]

        cmd = [
            AWS_CLI, "ec2-instance-connect", "open-tunnel",
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

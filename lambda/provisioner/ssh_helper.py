import logging
import time
from io import StringIO

import paramiko

logger = logging.getLogger(__name__)

PROMPT_USER = "> "
PROMPT_ADMIN = "# "


class ClishSession:
    """Interactive SSH session for the Service Gateway clish shell.

    The clish shell consumes space characters sent via normal stdin piping.
    This class uses paramiko's invoke_shell() and sends commands
    character-by-character to work around this behavior.
    """

    def __init__(self, host: str, username: str, private_key_pem: str, port: int = 22):
        self.host = host
        self.port = port
        self.username = username
        self._pkey = paramiko.Ed25519Key.from_private_key(StringIO(private_key_pem))
        self._client = None
        self._channel = None
        self._banner = ""

    def connect(self, timeout: int = 30) -> str:
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(
            self.host,
            port=self.port,
            username=self.username,
            pkey=self._pkey,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        self._channel = self._client.invoke_shell()
        self._channel.settimeout(timeout)
        self._banner = self._read_until(PROMPT_USER, timeout=timeout)
        return self._banner

    @property
    def banner(self) -> str:
        return self._banner

    def send_command(
        self, cmd: str, expect: str = PROMPT_ADMIN, timeout: int = 300
    ) -> str:
        for char in cmd:
            self._channel.send(char)
            time.sleep(0.01)
        self._channel.send("\r")
        return self._read_until(expect, timeout=timeout)

    def _read_until(self, pattern: str, timeout: int) -> str:
        buf = ""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._channel.recv_ready():
                chunk = self._channel.recv(8192).decode("utf-8", errors="replace")
                buf += chunk
                if pattern in buf:
                    return buf
            else:
                time.sleep(0.1)
        raise TimeoutError(
            f"Timed out after {timeout}s waiting for {pattern!r}. "
            f"Last output: {buf[-500:]}"
        )

    def close(self):
        if self._channel:
            self._channel.close()
        if self._client:
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()



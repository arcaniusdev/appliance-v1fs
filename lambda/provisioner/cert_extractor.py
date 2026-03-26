import logging
import socket
import ssl
import time

logger = logging.getLogger(__name__)

SG_TLS_HOSTNAME = "sg.sgi.xdr.trendmicro.com"


def extract_cert_pem(host: str, port: int = 443, timeout: int = 10, retries: int = 5) -> str:
    """Connect to host:port and return the server's certificate in PEM format."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for attempt in range(retries):
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=SG_TLS_HOSTNAME) as ssock:
                    der = ssock.getpeercert(binary_form=True)
            pem = ssl.DER_cert_to_PEM_cert(der)
            logger.info("Extracted certificate from %s:%d (%d bytes PEM)", host, port, len(pem))
            return pem
        except (ConnectionResetError, OSError) as e:
            logger.warning("Cert extraction attempt %d failed: %s", attempt + 1, e)
            if attempt < retries - 1:
                time.sleep(5)
    raise ConnectionError(f"Failed to extract cert from {host}:{port} after {retries} attempts")

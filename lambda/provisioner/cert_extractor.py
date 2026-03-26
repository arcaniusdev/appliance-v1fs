import logging
import socket
import ssl

logger = logging.getLogger(__name__)


def extract_cert_pem(host: str, port: int = 443, timeout: int = 10) -> str:
    """Connect to host:port and return the server's certificate in PEM format."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)

    pem = ssl.DER_cert_to_PEM_cert(der)
    logger.info("Extracted certificate from %s:%d (%d bytes PEM)", host, port, len(pem))
    return pem

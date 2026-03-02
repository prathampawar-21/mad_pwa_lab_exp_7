"""TLS/SSL certificate generation for dashboard HTTPS."""

import os
import ssl
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


def generate_self_signed_cert(
    cert_path: str,
    key_path: str,
    hostname: str = "localhost",
) -> bool:
    """Generate a self-signed TLS certificate using openssl."""
    try:
        result = subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:4096",
                "-keyout", key_path,
                "-out", cert_path,
                "-days", "365",
                "-nodes",
                "-subj", f"/CN={hostname}/O=QAMELEON/C=US",
            ],
            capture_output=True,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def get_ssl_context(
    cert_path: Optional[str] = None,
    key_path: Optional[str] = None,
) -> Optional[ssl.SSLContext]:
    """Get an SSL context for HTTPS.
    
    If cert/key paths not provided, generates temporary self-signed cert.
    Returns None if TLS setup fails.
    """
    if cert_path is None or key_path is None:
        tmp_dir = tempfile.mkdtemp(prefix="qameleon_tls_")
        cert_path = os.path.join(tmp_dir, "cert.pem")
        key_path = os.path.join(tmp_dir, "key.pem")
        if not generate_self_signed_cert(cert_path, key_path):
            return None

    if not Path(cert_path).exists() or not Path(key_path).exists():
        return None

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx
    except Exception:
        return None

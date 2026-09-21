import datetime
import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def sanitize_log_input(text: str, max_length: int = 512) -> str:
    if not text:
        return ''
    sanitized = re.sub(r'[\r\n\t]', ' ', text)
    sanitized = re.sub(r'[^\x20-\x7E]', '?', sanitized)
    return sanitized[:max_length]


def validate_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False


def anonymize_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            parts = ip.split('.')
            return f'{parts[0]}.{parts[1]}.{parts[2]}.xxx'
        else:
            parts = ip.split(':')
            if len(parts) >= 4:
                return f'{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}:xxxx:xxxx:xxxx:xxxx'
            return ip[:ip.rfind(':')] + ':xxxx'
    except Exception:
        return 'xxx.xxx.xxx.xxx'


def generate_self_signed_cert(cert_path: Path, key_path: Path, hostname: str = 'prod-server-01'):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(key_path, 0o600)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'California'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'ACME Corp'),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname), x509.DNSName('localhost')]), critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(cert_path, 0o644)
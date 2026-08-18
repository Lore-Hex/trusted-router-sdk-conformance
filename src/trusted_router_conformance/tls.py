"""Runtime-only TLS material for the loopback fault server."""

from __future__ import annotations

import ipaddress
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _key_usage(*, certificate_authority: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=not certificate_authority,
        content_commitment=False,
        key_encipherment=not certificate_authority,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=certificate_authority,
        crl_sign=certificate_authority,
        encipher_only=None,
        decipher_only=None,
    )


def _write_private_key(path: Path, private_key: rsa.RSAPrivateKey) -> None:
    encoded = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)


def _generate(directory: Path) -> tuple[Path, Path, Path]:
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(minutes=5)
    not_after = now + timedelta(hours=24)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "TrustedRouter Conformance Ephemeral Root")]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(certificate_authority=True), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.trustedrouter.com")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(certificate_authority=False), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("api.trustedrouter.com"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_cert_path = directory / "ca-cert.pem"
    server_cert_path = directory / "server-cert.pem"
    server_key_path = directory / "server-key.pem"
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    _write_private_key(server_key_path, server_key)
    # The CA key was never serialized. It becomes unreachable when this function
    # returns, immediately after signing the one server leaf.
    return ca_cert_path, server_cert_path, server_key_path


class EphemeralTLSMaterial:
    """Lazily create and own one fault server's disposable private PKI."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._temporary_directory: tempfile.TemporaryDirectory[str] | None = None
        self._ca_cert: Path | None = None
        self._server_cert: Path | None = None
        self._server_key: Path | None = None
        self._closed = False

    def _ensure(self) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("ephemeral TLS material has already been removed")
            if self._temporary_directory is not None:
                return
            temporary_directory = tempfile.TemporaryDirectory(
                prefix="trusted-router-conformance-tls-"
            )
            directory = Path(temporary_directory.name)
            os.chmod(directory, 0o700)
            try:
                ca_cert, server_cert, server_key = _generate(directory)
            except BaseException:
                temporary_directory.cleanup()
                raise
            self._temporary_directory = temporary_directory
            self._ca_cert = ca_cert
            self._server_cert = server_cert
            self._server_key = server_key

    @property
    def ca_cert_path(self) -> Path:
        self._ensure()
        assert self._ca_cert is not None
        return self._ca_cert

    @property
    def server_cert_path(self) -> Path:
        self._ensure()
        assert self._server_cert is not None
        return self._server_cert

    @property
    def server_key_path(self) -> Path:
        self._ensure()
        assert self._server_key is not None
        return self._server_key

    def discard_server_private_key(self) -> None:
        """Remove the leaf key after ``SSLContext`` has loaded it into memory."""

        with self._lock:
            self._ensure()
            assert self._server_key is not None
            self._server_key.unlink(missing_ok=True)

    def cleanup(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            temporary_directory = self._temporary_directory
            self._temporary_directory = None
            self._ca_cert = None
            self._server_cert = None
            self._server_key = None
        if temporary_directory is not None:
            temporary_directory.cleanup()

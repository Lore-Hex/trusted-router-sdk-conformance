from __future__ import annotations

import http.client
import json
import socket
import ssl
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from trusted_router_conformance.schema import load_scenario
from trusted_router_conformance.server import FaultServer


def _context(ca_cert_path: Path) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=ca_cert_path)


def _handshake(
    port: int,
    context: ssl.SSLContext,
    *,
    server_hostname: str,
) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        with context.wrap_socket(connection, server_hostname=server_hostname):
            pass


def test_tls_fault_server_replays_actions_and_records_wire_request() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "02-retry-503.json")
    with FaultServer(scenario) as server:
        for expected_status in (503, 200):
            connection = http.client.HTTPSConnection(
                "127.0.0.1", server.port, context=_context(server.ca_cert_path), timeout=2
            )
            connection.request(
                "POST",
                "/v1/chat/completions",
                body=b'{"model":"auto"}',
                headers={"content-type": "application/json", "x-test": "yes"},
            )
            response = connection.getresponse()
            assert response.status == expected_status
            response.read()
            connection.close()
        transcript = server.transcript()

    assert transcript["server_errors"] == []
    assert len(transcript["requests"]) == 2
    first = transcript["requests"][0]
    assert first["method"] == "POST"
    assert first["target"] == "/v1/chat/completions"
    assert first["headers"]["x-test"] == ["yes"]
    assert first["body_json"] == {"model": "auto"}


def test_fault_server_returns_599_after_scenario_is_exhausted() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "01-success.json")
    with FaultServer(scenario) as server:
        statuses: list[int] = []
        for _ in range(2):
            connection = http.client.HTTPSConnection(
                "127.0.0.1", server.port, context=_context(server.ca_cert_path), timeout=2
            )
            connection.request("POST", "/v1/chat/completions", body=json.dumps({}))
            response = connection.getresponse()
            statuses.append(response.status)
            response.read()
            connection.close()
        transcript = server.transcript()
    assert statuses == [200, 599]
    assert "unexpected request 2" in transcript["server_errors"][0]


def test_stalled_tls_peer_does_not_block_later_requests_or_shutdown() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "01-success.json")
    server = FaultServer(scenario)
    server.__enter__()
    stalled: socket.socket | None = None
    shutdown_thread: threading.Thread | None = None
    shutdown_done = threading.Event()
    shutdown_errors: list[BaseException] = []

    try:
        # This socket deliberately never sends a TLS ClientHello. It is connected
        # first so the server must not perform its handshake on the accept loop.
        stalled = socket.create_connection(("127.0.0.1", server.port), timeout=1)

        connection = http.client.HTTPSConnection(
            "127.0.0.1", server.port, context=_context(server.ca_cert_path), timeout=1
        )
        connection.request("POST", "/v1/chat/completions", body=json.dumps({}))
        response = connection.getresponse()
        assert response.status == 200
        response.read()
        connection.close()

        def shutdown() -> None:
            try:
                server.__exit__(None, None, None)
            except BaseException as exc:  # pragma: no cover - assertion reports it
                shutdown_errors.append(exc)
            finally:
                shutdown_done.set()

        shutdown_thread = threading.Thread(target=shutdown, daemon=True)
        shutdown_thread.start()
        assert shutdown_done.wait(timeout=2), "stalled TLS peer blocked server shutdown"
        assert shutdown_errors == []
    finally:
        if stalled is not None:
            stalled.close()
        if shutdown_thread is None:
            server.__exit__(None, None, None)
        else:
            shutdown_thread.join(timeout=2)


def test_tls_material_is_ephemeral_unique_and_a_valid_ca_leaf_chain() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "01-success.json")
    first = FaultServer(scenario)
    second = FaultServer(scenario)

    # Construction alone neither generates certificates nor writes a private key.
    assert first._tls_material._temporary_directory is None
    assert second._tls_material._temporary_directory is None

    # Simultaneous lazy access produces exactly one PKI for a server instance.
    with ThreadPoolExecutor(max_workers=4) as executor:
        generated_paths = list(executor.map(lambda _index: first.ca_cert_path, range(8)))
    assert len(set(generated_paths)) == 1
    first_directory = generated_paths[0].parent
    first_key = first._tls_material.server_key_path
    assert stat.S_IMODE(first_directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(first_key.stat().st_mode) == 0o600

    with first, second:
        first_ca = first.ca_cert_path
        second_ca = second.ca_cert_path
        second_directory = second_ca.parent
        first_leaf = first._tls_material.server_cert_path

        assert first_ca == generated_paths[0]
        assert first_directory != second_directory
        assert first_ca.read_bytes() != second_ca.read_bytes()
        assert {path.name for path in first_directory.iterdir()} == {
            "ca-cert.pem",
            "server-cert.pem",
        }

        ca_certificate = x509.load_pem_x509_certificate(first_ca.read_bytes())
        leaf_certificate = x509.load_pem_x509_certificate(first_leaf.read_bytes())
        ca_constraints = ca_certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        leaf_constraints = leaf_certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        assert ca_constraints.critical
        assert ca_constraints.value.ca
        assert ca_constraints.value.path_length == 0
        assert leaf_constraints.critical
        assert not leaf_constraints.value.ca

        ca_usage = ca_certificate.extensions.get_extension_for_class(x509.KeyUsage)
        leaf_usage = leaf_certificate.extensions.get_extension_for_class(x509.KeyUsage)
        assert ca_usage.critical
        assert ca_usage.value.key_cert_sign
        assert ca_usage.value.crl_sign
        assert not ca_usage.value.digital_signature
        assert leaf_usage.critical
        assert leaf_usage.value.digital_signature
        assert leaf_usage.value.key_encipherment
        assert not leaf_usage.value.key_cert_sign
        leaf_eku = leaf_certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert list(leaf_eku.value) == [ExtendedKeyUsageOID.SERVER_AUTH]

        names = leaf_certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        assert set(names.get_values_for_type(x509.DNSName)) == {
            "api.trustedrouter.com",
            "localhost",
        }
        assert [str(value) for value in names.get_values_for_type(x509.IPAddress)] == ["127.0.0.1"]
        assert ca_certificate.subject == ca_certificate.issuer
        assert leaf_certificate.issuer == ca_certificate.subject
        assert ca_certificate.signature_hash_algorithm.name == "sha256"
        assert leaf_certificate.signature_hash_algorithm.name == "sha256"
        assert isinstance(ca_certificate.public_key(), rsa.RSAPublicKey)
        assert isinstance(leaf_certificate.public_key(), rsa.RSAPublicKey)
        assert ca_certificate.public_key().key_size == 2048
        assert leaf_certificate.public_key().key_size == 2048
        now = datetime.now(timezone.utc)
        assert ca_certificate.not_valid_before_utc <= now <= ca_certificate.not_valid_after_utc
        assert leaf_certificate.not_valid_before_utc <= now <= leaf_certificate.not_valid_after_utc
        ca_certificate.public_key().verify(
            ca_certificate.signature,
            ca_certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            ca_certificate.signature_hash_algorithm,
        )
        ca_certificate.public_key().verify(
            leaf_certificate.signature,
            leaf_certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            leaf_certificate.signature_hash_algorithm,
        )

    assert not first_directory.exists()
    assert not second_directory.exists()


def test_tls_trust_is_scoped_to_one_run_and_both_hostnames_validate() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "01-success.json")
    with FaultServer(scenario) as trusted, FaultServer(scenario) as unrelated:
        _handshake(trusted.port, _context(trusted.ca_cert_path), server_hostname="127.0.0.1")
        _handshake(
            trusted.port,
            _context(trusted.ca_cert_path),
            server_hostname="api.trustedrouter.com",
        )

        with pytest.raises(ssl.SSLCertVerificationError):
            _handshake(
                trusted.port,
                ssl.create_default_context(),
                server_hostname="api.trustedrouter.com",
            )
        with pytest.raises(ssl.SSLCertVerificationError):
            _handshake(
                trusted.port,
                _context(unrelated.ca_cert_path),
                server_hostname="api.trustedrouter.com",
            )


def test_tls_material_is_removed_when_server_startup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "01-success.json")
    server = FaultServer(scenario)
    temporary_directory = server.ca_cert_path.parent

    def fail_after_context_load() -> None:
        raise RuntimeError("forced startup failure")

    monkeypatch.setattr(
        server._tls_material,
        "discard_server_private_key",
        fail_after_context_load,
    )
    with pytest.raises(RuntimeError, match="forced startup failure"):
        server.__enter__()

    assert not temporary_directory.exists()

from __future__ import annotations

import http.client
import json
import socket
import ssl
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

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


def test_beacon_between_actions_is_accepted_without_consuming_or_counting() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "02-retry-503.json")
    beacon_body = {
        "schema_version": 1,
        "batch_id": "batch-1",
        "events": [{"type": "request"}, {"type": "retry"}],
        "counters": [{"name": "attempts"}],
    }

    with FaultServer(scenario) as server:
        context = _context(server.ca_cert_path)
        statuses: list[int] = []
        for path, body in (
            ("/v1/chat/completions", b"{}"),
            ("/client-events?source=test", json.dumps(beacon_body).encode()),
            ("/v1/chat/completions", b"{}"),
        ):
            connection = http.client.HTTPSConnection(
                "127.0.0.1", server.port, context=context, timeout=2
            )
            connection.request("POST", path, body=body)
            response = connection.getresponse()
            statuses.append(response.status)
            response_body = response.read()
            connection.close()
            if path.startswith("/client-events"):
                assert json.loads(response_body) == {
                    "data": {
                        "accepted_events": 2,
                        "accepted_counters": 1,
                        "dropped": 0,
                    },
                    "policy": {},
                }
        transcript = server.transcript()

    assert statuses == [503, 202, 200]
    assert len(transcript["requests"]) == 2
    assert [request["index"] for request in transcript["requests"]] == [0, 1]
    assert transcript["server_errors"] == []
    assert transcript["beacons"] == [
        {
            "path": "/client-events",
            "byte_length": len(json.dumps(beacon_body).encode()),
            "json_parsed": True,
            "schema_version": 1,
            "events_count": 2,
            "counters_count": 1,
            "top_level_keys_recognized": True,
        }
    ]


def test_non_json_beacon_is_accepted_with_zero_counts() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "01-success.json")

    with FaultServer(scenario) as server:
        connection = http.client.HTTPSConnection(
            "127.0.0.1", server.port, context=_context(server.ca_cert_path), timeout=2
        )
        connection.request("POST", "/v1/client-events", body=b"not-json")
        response = connection.getresponse()
        response_body = response.read()
        connection.close()
        transcript = server.transcript()

    assert response.status == 202
    assert json.loads(response_body) == {
        "data": {"accepted_events": 0, "accepted_counters": 0, "dropped": 0},
        "policy": {},
    }
    assert transcript["requests"] == []
    assert transcript["beacons"][0]["json_parsed"] is False
    assert transcript["beacons"][0]["events_count"] == 0
    assert transcript["beacons"][0]["counters_count"] == 0
    assert transcript["server_errors"] == []


def test_beacon_after_last_action_is_not_an_unexpected_request() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "01-success.json")

    with FaultServer(scenario) as server:
        context = _context(server.ca_cert_path)
        statuses: list[int] = []
        for path in ("/v1/chat/completions", "/v1/client-events"):
            connection = http.client.HTTPSConnection(
                "127.0.0.1", server.port, context=context, timeout=2
            )
            connection.request("POST", path, body=b"{}")
            response = connection.getresponse()
            statuses.append(response.status)
            response.read()
            connection.close()
        transcript = server.transcript()

    assert statuses == [200, 202]
    assert len(transcript["requests"]) == 1
    assert len(transcript["beacons"]) == 1
    assert transcript["server_errors"] == []


def test_cross_origin_redirect_points_to_same_tls_sink_and_records_followup() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "14-cross-origin-redirect.json")
    with FaultServer(scenario) as server:
        context = _context(server.ca_cert_path)
        source = http.client.HTTPSConnection("127.0.0.1", server.port, context=context, timeout=2)
        source.request("POST", "/v1/chat/completions", body=b'{"secret":true}')
        response = source.getresponse()
        assert response.status == 307
        location = response.getheader("location")
        assert location is not None
        response.read()
        source.close()

        target = urlsplit(location)
        assert target.hostname == "localhost"
        assert target.port == server.port
        sink = http.client.HTTPSConnection("localhost", server.port, context=context, timeout=2)
        sink.request("POST", target.path, body=b'{"secret":true}')
        sink_response = sink.getresponse()
        assert sink_response.status == 599
        sink_response.read()
        sink.close()
        transcript = server.transcript()

    assert len(transcript["requests"]) == 2
    assert transcript["requests"][1]["target"] == "/redirect-sink"
    assert "unexpected request 2" in transcript["server_errors"][0]


def test_response_headers_can_precede_a_delayed_body() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "18-body-timeout.json")
    with FaultServer(scenario) as server:
        connection = http.client.HTTPSConnection(
            "127.0.0.1", server.port, context=_context(server.ca_cert_path), timeout=2
        )
        started = time.monotonic()
        connection.request("POST", "/v1/chat/completions", body=b"{}")
        response = connection.getresponse()
        headers_received = time.monotonic()
        assert response.status == 200
        assert response.read() == b'{"ok":true}'
        finished = time.monotonic()
        connection.close()

    assert headers_received >= started
    assert finished - headers_received >= 0.3


def test_expected_body_abort_suppresses_a_concurrent_idle_connection_reset() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "18-body-timeout.json")
    with FaultServer(scenario) as server:
        context = _context(server.ca_cert_path)
        connection = http.client.HTTPSConnection(
            "127.0.0.1", server.port, context=context, timeout=2
        )
        connection.request("POST", "/v1/chat/completions", body=b"{}")
        response = connection.getresponse()
        assert response.status == 200

        # A fetch implementation may establish a spare pooled TLS connection,
        # then reset it when the active response body is aborted. It has no HTTP
        # request/action, but belongs to the explicitly disconnect-tolerant call.
        _handshake(server.port, context, server_hostname="127.0.0.1")
        speculative = socket.create_connection(("127.0.0.1", server.port), timeout=1)
        speculative.close()
        connection.close()
        time.sleep(1.1)
        transcript = server.transcript()

    assert len(transcript["requests"]) == 1
    assert transcript["server_errors"] == []


def test_response_variant_follows_captured_stream_flag() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "22-chat-model-preservation.json")

    for stream, expected_type in ((False, "application/json"), (True, "text/event-stream")):
        with FaultServer(scenario) as server:
            connection = http.client.HTTPSConnection(
                "127.0.0.1", server.port, context=_context(server.ca_cert_path), timeout=2
            )
            body = json.dumps({"model": "auto", "stream": stream})
            connection.request("POST", "/v1/chat/completions", body=body)
            response = connection.getresponse()
            payload = response.read()
            connection.close()

        assert response.status == 200
        assert response.getheader("content-type") == expected_type
        if stream:
            assert payload.startswith(b"data: ")
            assert payload.endswith(b"data: [DONE]\n\n")
        else:
            assert json.loads(payload)["id"] == "chatcmpl-models"


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

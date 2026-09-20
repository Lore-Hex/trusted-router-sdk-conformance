"""A deterministic, dependency-free HTTP/1.1 fault server."""

from __future__ import annotations

import base64
import json
import socket
import socketserver
import ssl
import struct
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from trusted_router_conformance.schema import Scenario
from trusted_router_conformance.tls import EphemeralTLSMaterial

MAX_HEADER_BYTES = 64 * 1024
MAX_BODY_BYTES = 4 * 1024 * 1024
TLS_HANDSHAKE_TIMEOUT_SECONDS = 2.0
BEACON_PATHS = frozenset({"/v1/client-events", "/client-events"})
BEACON_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "batch_id",
        "instance_id",
        "seq",
        "sent_at_ms",
        "sdk",
        "synthetic",
        "dropped_since_last",
        "events",
        "counters",
    }
)


@dataclass(frozen=True)
class RecordedRequest:
    index: int
    method: str
    target: str
    http_version: str
    headers: dict[str, list[str]]
    body: bytes
    received_at_ns: int

    def as_dict(self) -> dict[str, Any]:
        try:
            body_text = self.body.decode("utf-8")
        except UnicodeDecodeError:
            body_text = None
        body_json: Any = None
        if body_text is not None:
            try:
                body_json = json.loads(body_text)
            except json.JSONDecodeError:
                pass
        return {
            "index": self.index,
            "method": self.method,
            "target": self.target,
            "http_version": self.http_version,
            "headers": self.headers,
            "body_base64": base64.b64encode(self.body).decode("ascii"),
            "body_text": body_text,
            "body_json": body_json,
            "received_at_ns": self.received_at_ns,
        }


def _request_path(request: RecordedRequest) -> str:
    return urlsplit(request.target).path


def _is_beacon(request: RecordedRequest) -> bool:
    return request.method == "POST" and _request_path(request) in BEACON_PATHS


def _record_beacon(request: RecordedRequest) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        body_json = json.loads(request.body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        body_json = None
        json_parsed = False
    else:
        json_parsed = True

    body_object = body_json if isinstance(body_json, dict) else None
    events = body_object.get("events") if body_object is not None else None
    counters = body_object.get("counters") if body_object is not None else None
    events_count = len(events) if isinstance(events, list) else 0
    counters_count = len(counters) if isinstance(counters, list) else 0
    beacon = {
        "path": _request_path(request),
        "byte_length": len(request.body),
        "json_parsed": json_parsed,
        "schema_version": (body_object.get("schema_version") if body_object is not None else None),
        "events_count": events_count,
        "counters_count": counters_count,
        "top_level_keys_recognized": (
            set(body_object).issubset(BEACON_TOP_LEVEL_KEYS) if body_object is not None else False
        ),
    }
    response = {
        "kind": "response",
        "status": 202,
        "json": {
            "data": {
                "accepted_events": events_count,
                "accepted_counters": counters_count,
                "dropped": 0,
            },
            "policy": {},
        },
    }
    return beacon, response


class _State:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario
        self.lock = threading.Lock()
        self.requests: list[RecordedRequest] = []
        self.beacons: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self._active_disconnect_tolerant_responses = 0

    def record(self, request: RecordedRequest) -> dict[str, Any]:
        with self.lock:
            if _is_beacon(request):
                beacon, response = _record_beacon(request)
                self.beacons.append(beacon)
                return response
            self.requests.append(request)
            index = len(self.requests) - 1
            if index >= len(self.scenario.actions):
                self.errors.append(
                    f"unexpected request {index + 1}: scenario has "
                    f"{len(self.scenario.actions)} actions"
                )
                return {
                    "kind": "response",
                    "status": 599,
                    "json": {"error": "conformance scenario exhausted"},
                }
            return self.scenario.actions[index]

    def begin_disconnect_tolerant_response(self) -> None:
        with self.lock:
            self._active_disconnect_tolerant_responses += 1

    def end_disconnect_tolerant_response(self) -> None:
        with self.lock:
            self._active_disconnect_tolerant_responses -= 1

    def has_active_disconnect_tolerant_response(self) -> bool:
        with self.lock:
            return self._active_disconnect_tolerant_responses > 0


class _EmptyConnection(ConnectionError):
    """A peer closed without sending any HTTP request bytes."""


def _read_request(sock: socket.socket, index: int) -> RecordedRequest:
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            if not buffer:
                raise _EmptyConnection("peer closed without sending request bytes")
            raise ConnectionError("peer closed before request headers")
        buffer.extend(chunk)
        if len(buffer) > MAX_HEADER_BYTES:
            raise ValueError("request headers exceed harness limit")
    header_bytes, body = bytes(buffer).split(b"\r\n\r\n", 1)
    lines = header_bytes.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        raise ValueError(f"malformed request line: {lines[0]!r}")
    method, target, http_version = parts
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if ":" not in line:
            raise ValueError(f"malformed header line: {line!r}")
        name, value = line.split(":", 1)
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    raw_length = headers.get("content-length", ["0"])[-1]
    try:
        length = int(raw_length)
    except ValueError as exc:
        raise ValueError(f"invalid content-length: {raw_length!r}") from exc
    if length < 0 or length > MAX_BODY_BYTES:
        raise ValueError("request body exceeds harness limit")
    while len(body) < length:
        chunk = sock.recv(min(65536, length - len(body)))
        if not chunk:
            raise ConnectionError("peer closed before request body")
        body += chunk
    return RecordedRequest(
        index=index,
        method=method,
        target=target,
        http_version=http_version,
        headers=headers,
        body=body[:length],
        received_at_ns=time.monotonic_ns(),
    )


def _body(action: dict[str, Any], *, stream_requested: bool) -> tuple[bytes, str | None]:
    if stream_requested and "stream_text" in action:
        return str(action["stream_text"]).encode(), "text/event-stream"
    if "json" in action:
        return (
            json.dumps(action["json"], separators=(",", ":"), ensure_ascii=False).encode(),
            "application/json",
        )
    if "text" in action:
        return str(action["text"]).encode(), None
    if "body_base64" in action:
        return base64.b64decode(action["body_base64"], validate=True), None
    return b"", None


def _requests_stream(request: RecordedRequest) -> bool:
    try:
        body = json.loads(request.body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(body, dict) and body.get("stream") is True


def _send_response(
    sock: socket.socket,
    action: dict[str, Any],
    *,
    truncate: bool,
    stream_requested: bool,
    redirect_location: str | None = None,
) -> None:
    status = int(action["status"])
    try:
        reason = HTTPStatus(status).phrase
    except ValueError:
        reason = "Harness Response"
    body, inferred_content_type = _body(action, stream_requested=stream_requested)
    headers = {str(key): str(value) for key, value in action.get("headers", {}).items()}
    if redirect_location is not None:
        headers["Location"] = redirect_location
    lower_names = {key.lower() for key in headers}
    advertised = len(body) + (int(action.get("missing_bytes", 17)) if truncate else 0)
    if "content-length" not in lower_names:
        headers["Content-Length"] = str(advertised)
    if "content-type" not in lower_names and inferred_content_type is not None:
        headers["Content-Type"] = inferred_content_type
    if "connection" not in lower_names:
        headers["Connection"] = "close"
    head = [f"HTTP/1.1 {status} {reason}\r\n"]
    head.extend(f"{name}: {value}\r\n" for name, value in headers.items())
    head.append("\r\n")
    sock.sendall("".join(head).encode("iso-8859-1"))
    body_delay_ms = int(action.get("body_delay_ms", 0))
    if body_delay_ms:
        time.sleep(body_delay_ms / 1000)
    if truncate:
        prefix_length = action.get("send_bytes")
        if prefix_length is None:
            prefix_length = max(1, len(body) // 2) if body else 0
        sock.sendall(body[: int(prefix_length)])
        _reset(sock)
    elif body:
        sock.sendall(body)


def _reset(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        state: _State = self.server.state  # type: ignore[attr-defined]
        sock: socket.socket = self.request
        sock.settimeout(10)
        action: dict[str, Any] | None = None
        disconnect_tolerant = False
        try:
            with state.lock:
                index = len(state.requests)
            request = _read_request(sock, index)
            action = state.record(request)
            disconnect_tolerant = action.get("allow_client_disconnect") is True
            if disconnect_tolerant:
                state.begin_disconnect_tolerant_response()
            delay_ms = int(action.get("delay_ms", 0))
            if delay_ms:
                time.sleep(delay_ms / 1000)
            kind = action["kind"]
            if kind == "disconnect":
                _reset(sock)
                return
            redirect_location = None
            if kind == "cross_origin_redirect":
                port = int(self.server.server_address[1])  # type: ignore[attr-defined]
                redirect_location = f"https://localhost:{port}/redirect-sink"
            _send_response(
                sock,
                action,
                truncate=kind == "truncated_response",
                stream_requested=_requests_stream(request),
                redirect_location=redirect_location,
            )
        except (ConnectionError, OSError, ValueError) as exc:
            if isinstance(exc, _EmptyConnection):
                return
            # Some clients speculatively open another pooled connection and reset
            # it when aborting the in-flight body read. That auxiliary handler has
            # no action of its own, so suppress it only while an explicitly
            # disconnect-tolerant scenario response is still active.
            if disconnect_tolerant or state.has_active_disconnect_tolerant_response():
                return
            with state.lock:
                state.errors.append(f"server connection error: {type(exc).__name__}: {exc}")
        finally:
            if disconnect_tolerant:
                state.end_disconnect_tolerant_response()


class _ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def finish_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        """Complete TLS in the connection worker before HTTP request handling.

        Wrapping the listening socket makes ``accept()`` perform the TLS handshake
        on the ``serve_forever`` thread. A peer that opens TCP and sends nothing
        can then prevent both later accepts and a clean shutdown. Keep the listener
        plain and put the bounded handshake in the per-connection worker instead.
        """
        context: ssl.SSLContext = self.tls_context  # type: ignore[attr-defined]
        tls_request: ssl.SSLSocket | None = None
        try:
            request.settimeout(TLS_HANDSHAKE_TIMEOUT_SECONDS)
            tls_request = context.wrap_socket(
                request,
                server_side=True,
                do_handshake_on_connect=False,
            )
            tls_request.do_handshake()
        except OSError as exc:
            failed_request = tls_request if tls_request is not None else request
            failed_request.close()
            state: _State = self.state  # type: ignore[attr-defined]
            if state.has_active_disconnect_tolerant_response():
                return
            with state.lock:
                state.errors.append(f"TLS handshake error: {type(exc).__name__}: {exc}")
            return

        try:
            super().finish_request(tls_request, client_address)
        finally:
            tls_request.close()


class FaultServer:
    """Context-managed fault server for one scenario execution."""

    def __init__(self, scenario: Scenario) -> None:
        self._state = _State(scenario)
        self._server = _ThreadingServer(("127.0.0.1", 0), _Handler)
        self._server.state = self._state  # type: ignore[attr-defined]
        self._tls_material = EphemeralTLSMaterial()
        self._lifecycle_lock = threading.RLock()
        self._tls_prepared = False
        self._started = False
        self._closed = False
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"conformance-{scenario.name}",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def physical_origin(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    @property
    def logical_base_url(self) -> str:
        return f"https://api.trustedrouter.com:{self.port}/v1"

    @property
    def ca_cert_path(self) -> Path:
        """Path to this server run's disposable CA certificate."""

        return self._tls_material.ca_cert_path

    def _prepare_tls(self) -> None:
        with self._lifecycle_lock:
            if self._tls_prepared:
                return
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(
                certfile=self._tls_material.server_cert_path,
                keyfile=self._tls_material.server_key_path,
            )
            self._tls_material.discard_server_private_key()
            self._server.tls_context = context  # type: ignore[attr-defined]
            self._tls_prepared = True

    def transcript(self) -> dict[str, Any]:
        with self._state.lock:
            return {
                "protocol_version": 1,
                "requests": [request.as_dict() for request in self._state.requests],
                "beacons": [dict(beacon) for beacon in self._state.beacons],
                "server_errors": list(self._state.errors),
            }

    def __enter__(self) -> FaultServer:
        with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError("fault server has already been closed")
            if self._started:
                raise RuntimeError("fault server has already been started")
            try:
                self._prepare_tls()
                self._thread.start()
            except BaseException:
                self._closed = True
                self._server.server_close()
                self._tls_material.cleanup()
                raise
            self._started = True
        return self

    def __exit__(self, *_exc: object) -> None:
        with self._lifecycle_lock:
            if self._closed:
                return
            self._closed = True
            started = self._started
        try:
            if started:
                self._server.shutdown()
            self._server.server_close()
            if started:
                self._thread.join(timeout=2)
        finally:
            self._tls_material.cleanup()

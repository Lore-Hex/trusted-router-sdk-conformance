#!/usr/bin/env python3
"""Black-box adapter for the checked-out Python SDK."""

from __future__ import annotations

import json
import os
import sys
from typing import Any
from urllib.parse import urlsplit


def _env(name: str) -> str:
    value = os.environ.get(f"TR_CONFORMANCE_{name}")
    if value is None:
        raise RuntimeError(f"missing TR_CONFORMANCE_{name}")
    return value


def _emit(outcome: str, *, value: Any = None, error: BaseException | None = None) -> None:
    result: dict[str, Any] = {
        "protocol_version": 1,
        "sdk": "python",
        "scenario": os.environ.get("TR_CONFORMANCE_SCENARIO", "unknown"),
        "outcome": outcome,
    }
    if outcome == "success":
        result["value"] = value
        result["error"] = None
    else:
        result["value"] = None
        detail = {
            "type": type(error).__name__ if error is not None else "UnknownError",
            "message": str(error) if error is not None else "unknown error",
        }
        status_code = getattr(error, "status_code", None)
        if isinstance(status_code, int) and not isinstance(status_code, bool):
            detail["status_code"] = status_code
        result["error"] = detail
    print(json.dumps(result, separators=(",", ":"), ensure_ascii=False), flush=True)


def main() -> None:
    sdk_root = _env("SDK_ROOT")
    sys.path.insert(0, os.path.join(sdk_root, "src"))

    import httpx
    from trustedrouter import TrustedRouter

    physical = urlsplit(_env("PHYSICAL_ORIGIN"))
    if physical.hostname is None or physical.port is None:
        raise RuntimeError("physical origin must contain a host and port")

    class RewriteTransport(httpx.BaseTransport):
        def __init__(self) -> None:
            self._inner = httpx.HTTPTransport(retries=0, verify=_env("CA_CERT"))

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            rewritten = request.url.copy_with(
                scheme=physical.scheme,
                host=physical.hostname,
                port=physical.port,
            )
            forwarded = httpx.Request(
                request.method,
                rewritten,
                headers=request.headers,
                stream=request.stream,
                extensions=request.extensions,
            )
            return self._inner.handle_request(forwarded)

        def close(self) -> None:
            self._inner.close()

    class NullTelemetrySink:
        def on_request(self, _event: object, _counters: object) -> None:
            pass

    timeout_seconds = int(_env("TIMEOUT_MS")) / 1000
    transport = RewriteTransport()
    http_client = httpx.Client(transport=transport, timeout=timeout_seconds, trust_env=False)
    client = TrustedRouter(
        api_key="tr-conformance-key",
        base_url=_env("LOGICAL_BASE_URL"),
        control_base_url=_env("LOGICAL_BASE_URL"),
        client=http_client,
        max_retries=int(_env("MAX_RETRIES")),
        regional_failover=False,
        regional_affinity=False,
        telemetry=_env("TELEMETRY") == "1",
        _telemetry_sink=NullTelemetrySink(),
    )
    try:
        kwargs: dict[str, Any] = {
            "json": json.loads(_env("BODY_JSON")),
            "headers": json.loads(_env("HEADERS_JSON")),
            "timeout": timeout_seconds,
        }
        idempotency_key = _env("IDEMPOTENCY_KEY")
        if idempotency_key:
            kwargs["idempotency_key"] = idempotency_key
        value = client.request(_env("METHOD"), _env("PATH"), **kwargs)
    except BaseException as exc:  # Driver must normalize the SDK's entire error surface.
        _emit("error", error=exc)
    else:
        _emit("success", value=value)
    finally:
        client.close()
        http_client.close()


if __name__ == "__main__":
    try:
        main()
    except BaseException as exc:
        _emit("error", error=exc)

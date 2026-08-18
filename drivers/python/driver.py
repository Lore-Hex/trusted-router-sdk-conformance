#!/usr/bin/env python3
"""Black-box adapter for the checked-out Python SDK."""

from __future__ import annotations

import asyncio
import dataclasses
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


def _jsonable(value: Any) -> Any:
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return model_dump(mode="json")
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    return value


def _emit(outcome: str, *, value: Any = None, error: BaseException | None = None) -> None:
    result: dict[str, Any] = {
        "protocol_version": 1,
        "sdk": "python",
        "scenario": os.environ.get("TR_CONFORMANCE_SCENARIO", "unknown"),
        "outcome": outcome,
    }
    if outcome == "success":
        result["value"] = _jsonable(value)
        result["error"] = None
    else:
        result["value"] = None
        error_type = type(error).__name__ if error is not None else "UnknownError"
        message = str(error) if error is not None else "unknown error"
        result["error"] = {
            "type": error_type,
            "message": message or error_type,
        }
        status_code = getattr(error, "status_code", None)
        if isinstance(status_code, int) and not isinstance(status_code, bool):
            result["error"]["status_code"] = status_code
    print(json.dumps(result, separators=(",", ":"), ensure_ascii=False), flush=True)


async def _main() -> None:
    sdk_root = _env("SDK_ROOT")
    sys.path.insert(0, os.path.join(sdk_root, "src"))

    import httpx
    from trustedrouter import AsyncTrustedRouter
    from trustedrouter.oauth import exchange_oauth_key_async

    physical = urlsplit(_env("PHYSICAL_ORIGIN"))
    if physical.hostname is None or physical.port is None:
        raise RuntimeError("physical origin must contain a host and port")

    class RewriteTransport(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self._inner = httpx.AsyncHTTPTransport(retries=0, verify=_env("CA_CERT"))

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
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
            return await self._inner.handle_async_request(forwarded)

        async def aclose(self) -> None:
            await self._inner.aclose()

    class NullTelemetrySink:
        def on_request(self, _event: object, _counters: object) -> None:
            pass

    timeout_seconds = int(_env("TIMEOUT_MS")) / 1000
    default_headers = json.loads(_env("DEFAULT_HEADERS_JSON"))
    transport = RewriteTransport()
    http_client = httpx.AsyncClient(
        transport=transport,
        timeout=timeout_seconds,
        trust_env=False,
        headers=default_headers,
    )
    client = AsyncTrustedRouter(
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

    body = json.loads(_env("BODY_JSON"))
    headers = json.loads(_env("HEADERS_JSON"))
    idempotency_key = _env("IDEMPOTENCY_KEY") or None
    entrypoint = _env("ENTRYPOINT")

    async def invoke() -> Any:
        if entrypoint == "generic_json":
            kwargs: dict[str, Any] = {
                "json": body,
                "headers": headers,
                "timeout": timeout_seconds,
            }
            if idempotency_key is not None:
                kwargs["idempotency_key"] = idempotency_key
            return await client.request(_env("METHOD"), _env("PATH"), **kwargs)

        if entrypoint in {"chat_completions", "chat_stream_collect"}:
            options = dict(body)
            model = options.pop("model", "trustedrouter/auto")
            messages = options.pop("messages")
            options.pop("stream", None)
            return await client.chat_completions(
                model=model,
                messages=messages,
                extra_headers=headers,
                idempotency_key=idempotency_key,
                timeout=timeout_seconds,
                **options,
            )

        if entrypoint == "responses":
            options = dict(body)
            model = options.pop("model", "trustedrouter/auto")
            input_value = options.pop("input")
            instructions = options.pop("instructions", None)
            options.pop("stream", None)
            return await client.responses(
                model=model,
                input=input_value,
                instructions=instructions,
                extra_headers=headers,
                idempotency_key=idempotency_key,
                timeout=timeout_seconds,
                **options,
            )

        if entrypoint == "oauth_exchange":
            return await exchange_oauth_key_async(
                code=body["code"],
                code_verifier=body.get("code_verifier"),
                code_challenge_method=body.get("code_challenge_method"),
                base_url=_env("LOGICAL_BASE_URL"),
                client=http_client,
                timeout=timeout_seconds,
            )

        raise RuntimeError(f"unsupported conformance entrypoint {entrypoint!r}")

    try:
        task = asyncio.create_task(invoke())
        cancel_after = _env("CANCEL_AFTER_MS")
        cancel_handle = None
        if cancel_after:
            cancel_handle = asyncio.get_running_loop().call_later(
                int(cancel_after) / 1000,
                task.cancel,
            )
        try:
            value = await task
        finally:
            if cancel_handle is not None:
                cancel_handle.cancel()
    except BaseException as exc:  # Driver must normalize the SDK's entire error surface.
        _emit("error", error=exc)
    else:
        _emit("success", value=value)
    finally:
        await client.aclose()
        await http_client.aclose()


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except BaseException as exc:
        _emit("error", error=exc)

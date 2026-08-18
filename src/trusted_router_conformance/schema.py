"""Strict scenario and driver-manifest loading.

The on-disk format is JSON on purpose: every SDK driver can consume the same
values without acquiring a YAML or TOML parser merely to run the harness.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = 1
ACTION_KINDS = {"response", "disconnect", "truncated_response"}
OUTCOMES = {"success", "error"}
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_SCENARIO_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_CAPABILITY = re.compile(r"[a-z][a-z0-9_]*")


class SchemaError(ValueError):
    """Raised when a scenario or driver manifest is invalid."""


def _object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise SchemaError(f"{where} must be a JSON object with string keys")
    return value


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise SchemaError(f"{where} must be a non-empty string")
    return value


def _only_keys(value: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise SchemaError(f"{where} contains unknown fields: {', '.join(unknown)}")


def _string_list(value: Any, where: str, *, pattern: re.Pattern[str] | None = None) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise SchemaError(f"{where} must be an array of non-empty strings")
    if len(set(value)) != len(value):
        raise SchemaError(f"{where} must not contain duplicates")
    if pattern is not None:
        invalid = [item for item in value if pattern.fullmatch(item) is None]
        if invalid:
            raise SchemaError(f"{where} contains invalid values: {', '.join(invalid)}")
    return value


def _headers(value: Any, where: str) -> dict[str, str]:
    headers = _object(value, where)
    for name, header_value in headers.items():
        if _HEADER_NAME.fullmatch(name) is None:
            raise SchemaError(f"{where} contains invalid header name {name!r}")
        if not isinstance(header_value, str) or "\r" in header_value or "\n" in header_value:
            raise SchemaError(f"{where}.{name} must be a string without CR or LF")
    return headers


def _header_rules(value: Any, where: str) -> dict[str, Any]:
    rules = _object(value, where)
    for name, candidate in rules.items():
        if _HEADER_NAME.fullmatch(name) is None:
            raise SchemaError(f"{where} contains invalid header name {name!r}")
        if isinstance(candidate, str):
            continue
        rule = _object(candidate, f"{where}.{name}")
        _only_keys(rule, {"absent", "present", "matches"}, f"{where}.{name}")
        if not rule:
            raise SchemaError(f"{where}.{name} rule must not be empty")
        for boolean_key in ("absent", "present"):
            if boolean_key in rule and rule[boolean_key] is not True:
                raise SchemaError(f"{where}.{name}.{boolean_key} must be true")
        if rule.get("absent") and ("present" in rule or "matches" in rule):
            raise SchemaError(f"{where}.{name}.absent cannot be combined with another rule")
        if "matches" in rule:
            pattern = rule["matches"]
            if not isinstance(pattern, str) or not pattern:
                raise SchemaError(f"{where}.{name}.matches must be a non-empty string")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise SchemaError(f"{where}.{name}.matches is invalid: {exc}") from exc
    return rules


@dataclass(frozen=True)
class Operation:
    method: str
    path: str
    body: Any
    headers: dict[str, str]
    idempotency_key: str | None


@dataclass(frozen=True)
class ClientConfig:
    max_retries: int
    timeout_ms: int
    telemetry: bool


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    requires: tuple[str, ...]
    operation: Operation
    client: ClientConfig
    actions: tuple[dict[str, Any], ...]
    expect: dict[str, Any]
    path: Path


@dataclass(frozen=True)
class DriverManifest:
    sdk: str
    command: tuple[str, ...]
    capabilities: frozenset[str]
    root_name: str
    path: Path


def load_scenario(path: str | Path) -> Scenario:
    source = Path(path).resolve()
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaError(f"cannot load scenario {source}: {exc}") from exc
    data = _object(raw, str(source))
    _only_keys(
        data,
        {
            "protocol_version",
            "name",
            "description",
            "requires",
            "operation",
            "client",
            "actions",
            "expect",
        },
        str(source),
    )
    version = data.get("protocol_version")
    if version != PROTOCOL_VERSION:
        raise SchemaError(f"{source}: protocol_version must be {PROTOCOL_VERSION}, got {version!r}")
    name = _string(data.get("name"), f"{source}.name")
    if _SCENARIO_NAME.fullmatch(name) is None:
        raise SchemaError(f"{source}.name must use lowercase kebab-case")
    description = _string(data.get("description"), f"{source}.description")

    requires_raw = _string_list(data.get("requires", []), f"{source}.requires", pattern=_CAPABILITY)

    operation_raw = _object(data.get("operation"), f"{source}.operation")
    _only_keys(
        operation_raw,
        {"method", "path", "body", "headers", "idempotency_key"},
        f"{source}.operation",
    )
    method = _string(operation_raw.get("method"), f"{source}.operation.method").upper()
    path_value = _string(operation_raw.get("path"), f"{source}.operation.path")
    if not path_value.startswith("/") or path_value.startswith("//"):
        raise SchemaError(f"{source}.operation.path must start with one slash")
    headers_raw = _headers(operation_raw.get("headers", {}), f"{source}.operation.headers")
    idempotency_key = operation_raw.get("idempotency_key")
    if idempotency_key is not None:
        idempotency_key = _string(idempotency_key, f"{source}.operation.idempotency_key")

    client_raw = _object(data.get("client", {}), f"{source}.client")
    _only_keys(
        client_raw,
        {"max_retries", "timeout_ms", "telemetry"},
        f"{source}.client",
    )
    max_retries = client_raw.get("max_retries", 0)
    timeout_ms = client_raw.get("timeout_ms", 2_000)
    telemetry = client_raw.get("telemetry", False)
    if not isinstance(max_retries, int) or isinstance(max_retries, bool) or max_retries < 0:
        raise SchemaError(f"{source}.client.max_retries must be a non-negative integer")
    if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or timeout_ms <= 0:
        raise SchemaError(f"{source}.client.timeout_ms must be a positive integer")
    if not isinstance(telemetry, bool):
        raise SchemaError(f"{source}.client.telemetry must be a boolean")

    actions_raw = data.get("actions")
    if not isinstance(actions_raw, list) or not actions_raw:
        raise SchemaError(f"{source}.actions must be a non-empty array")
    actions: list[dict[str, Any]] = []
    for index, candidate in enumerate(actions_raw):
        where = f"{source}.actions[{index}]"
        action = _object(candidate, where)
        kind = action.get("kind")
        if kind not in ACTION_KINDS:
            raise SchemaError(
                f"{source}.actions[{index}].kind must be one of {sorted(ACTION_KINDS)}"
            )
        allowed_action_keys = {"kind", "delay_ms"}
        if kind in {"response", "truncated_response"}:
            allowed_action_keys.update({"status", "headers", "json", "text", "body_base64"})
        if kind == "truncated_response":
            allowed_action_keys.update({"missing_bytes", "send_bytes"})
        _only_keys(action, allowed_action_keys, where)
        delay_ms = action.get("delay_ms", 0)
        if not isinstance(delay_ms, int) or isinstance(delay_ms, bool) or delay_ms < 0:
            raise SchemaError(f"{source}.actions[{index}].delay_ms must be non-negative")
        if kind in {"response", "truncated_response"}:
            status = action.get("status")
            if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
                raise SchemaError(f"{source}.actions[{index}].status must be 100..599")
            _headers(action.get("headers", {}), f"{where}.headers")
            body_keys = [key for key in ("json", "text", "body_base64") if key in action]
            if len(body_keys) > 1:
                raise SchemaError(
                    f"{source}.actions[{index}] may contain only one response body field"
                )
            if "text" in action and not isinstance(action["text"], str):
                raise SchemaError(f"{where}.text must be a string")
            if "body_base64" in action:
                if not isinstance(action["body_base64"], str):
                    raise SchemaError(f"{where}.body_base64 must be a string")
                try:
                    base64.b64decode(action["body_base64"], validate=True)
                except (ValueError, binascii.Error) as exc:
                    raise SchemaError(f"{where}.body_base64 is invalid") from exc
            for length_key in ("missing_bytes", "send_bytes"):
                if length_key in action and (
                    not isinstance(action[length_key], int)
                    or isinstance(action[length_key], bool)
                    or action[length_key] < 0
                ):
                    raise SchemaError(f"{where}.{length_key} must be non-negative")
        actions.append(action)

    expect = _object(data.get("expect"), f"{source}.expect")
    _only_keys(
        expect,
        {
            "outcome",
            "attempts",
            "body_json_subset",
            "value_json_subset",
            "same_headers",
            "headers",
            "attempt_headers",
            "error_status",
        },
        f"{source}.expect",
    )
    outcome = expect.get("outcome")
    if outcome not in OUTCOMES:
        raise SchemaError(f"{source}.expect.outcome must be one of {sorted(OUTCOMES)}")
    error_status = expect.get("error_status")
    if error_status is not None:
        if outcome != "error":
            raise SchemaError(f"{source}.expect.error_status requires outcome=error")
        if (
            not isinstance(error_status, int)
            or isinstance(error_status, bool)
            or not 100 <= error_status <= 599
        ):
            raise SchemaError(f"{source}.expect.error_status must be 100..599")
    attempts = expect.get("attempts")
    if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts <= 0:
        raise SchemaError(f"{source}.expect.attempts must be a positive integer")
    if len(actions) != attempts:
        raise SchemaError(
            f"{source}: actions has {len(actions)} entries but expect.attempts is {attempts}"
        )
    _string_list(
        expect.get("same_headers", []),
        f"{source}.expect.same_headers",
        pattern=_HEADER_NAME,
    )
    _header_rules(expect.get("headers", {}), f"{source}.expect.headers")
    attempt_headers = expect.get("attempt_headers", [])
    if not isinstance(attempt_headers, list):
        raise SchemaError(f"{source}.expect.attempt_headers must be an array")
    if attempt_headers and len(attempt_headers) != attempts:
        raise SchemaError(
            f"{source}.expect.attempt_headers must contain exactly {attempts} entries"
        )
    for index, rules in enumerate(attempt_headers):
        _header_rules(rules, f"{source}.expect.attempt_headers[{index}]")

    return Scenario(
        name=name,
        description=description,
        requires=tuple(requires_raw),
        operation=Operation(
            method=method,
            path=path_value,
            body=operation_raw.get("body"),
            headers=dict(headers_raw),
            idempotency_key=idempotency_key,
        ),
        client=ClientConfig(
            max_retries=max_retries,
            timeout_ms=timeout_ms,
            telemetry=telemetry,
        ),
        actions=tuple(actions),
        expect=expect,
        path=source,
    )


def load_driver_manifest(path: str | Path) -> DriverManifest:
    source = Path(path).resolve()
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaError(f"cannot load driver manifest {source}: {exc}") from exc
    data = _object(raw, str(source))
    _only_keys(
        data,
        {"protocol_version", "sdk", "root_name", "command", "capabilities"},
        str(source),
    )
    if data.get("protocol_version") != PROTOCOL_VERSION:
        raise SchemaError(f"{source}: protocol_version must be {PROTOCOL_VERSION}")
    sdk = _string(data.get("sdk"), f"{source}.sdk")
    if _CAPABILITY.fullmatch(sdk) is None:
        raise SchemaError(f"{source}.sdk must use lowercase snake-case")
    root_name = _string(data.get("root_name"), f"{source}.root_name")
    command_raw = data.get("command")
    if (
        not isinstance(command_raw, list)
        or not command_raw
        or not all(isinstance(value, str) and value for value in command_raw)
    ):
        raise SchemaError(f"{source}.command must be a non-empty string array")
    capabilities_raw = _string_list(
        data.get("capabilities", []), f"{source}.capabilities", pattern=_CAPABILITY
    )
    return DriverManifest(
        sdk=sdk,
        command=tuple(command_raw),
        capabilities=frozenset(capabilities_raw),
        root_name=root_name,
        path=source,
    )

"""Shared assertions over normalized driver output and captured wire traffic."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from trusted_router_conformance.schema import Scenario


@dataclass(frozen=True)
class Verification:
    ok: bool
    failures: tuple[str, ...]


def _one(headers: dict[str, Any], name: str, where: str, failures: list[str]) -> str | None:
    values = headers.get(name.lower())
    if values is None:
        return None
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        failures.append(f"{where}: header {name!r} has malformed transcript value")
        return None
    if len(values) != 1:
        failures.append(f"{where}: expected one {name!r} header, got {len(values)}")
        return None
    return values[0]


def _matches_subset(actual: Any, expected: Any, path: str, failures: list[str]) -> None:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            failures.append(f"{path}: expected object subset, got {actual!r}")
            return
        for key, value in expected.items():
            if key not in actual:
                failures.append(f"{path}: missing key {key!r}")
            else:
                _matches_subset(actual[key], value, f"{path}.{key}", failures)
        return
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) < len(expected):
            failures.append(f"{path}: expected list prefix {expected!r}, got {actual!r}")
            return
        for index, value in enumerate(expected):
            _matches_subset(actual[index], value, f"{path}[{index}]", failures)
        return
    if actual != expected:
        failures.append(f"{path}: expected {expected!r}, got {actual!r}")


def _check_header_rule(
    actual: str | None, rule: Any, name: str, where: str, failures: list[str]
) -> None:
    if isinstance(rule, str):
        if actual != rule:
            failures.append(f"{where}: header {name!r} expected {rule!r}, got {actual!r}")
        return
    if not isinstance(rule, dict):
        failures.append(f"{where}: invalid rule for header {name!r}: {rule!r}")
        return
    if rule.get("absent") is True:
        if actual is not None:
            failures.append(f"{where}: header {name!r} must be absent, got {actual!r}")
        return
    if rule.get("present") is True and actual is None:
        failures.append(f"{where}: header {name!r} must be present")
        return
    pattern = rule.get("matches")
    if pattern is not None:
        if not isinstance(pattern, str):
            failures.append(f"{where}: matches for {name!r} must be a string")
        elif actual is None or re.fullmatch(pattern, actual) is None:
            failures.append(f"{where}: header {name!r} value {actual!r} does not match /{pattern}/")


def verify(
    scenario: Scenario,
    result: dict[str, Any],
    transcript: dict[str, Any],
    *,
    expected_sdk: str | None = None,
) -> Verification:
    failures: list[str] = []
    if result.get("protocol_version") != 1:
        failures.append("driver result has wrong protocol_version")
    if expected_sdk is not None and result.get("sdk") != expected_sdk:
        failures.append(f"driver result sdk expected {expected_sdk!r}, got {result.get('sdk')!r}")
    if result.get("scenario") != scenario.name:
        failures.append(
            f"driver result scenario expected {scenario.name!r}, got {result.get('scenario')!r}"
        )
    actual_outcome = result.get("outcome")
    if actual_outcome != scenario.expect["outcome"]:
        failures.append(
            f"driver outcome expected {scenario.expect['outcome']!r}, got {actual_outcome!r}: "
            f"{result.get('error')!r}"
        )
    if "value" not in result or "error" not in result:
        failures.append("driver result must contain both value and error fields")
    elif actual_outcome == "success":
        if result["error"] is not None:
            failures.append(f"successful driver result has non-null error: {result['error']!r}")
        if "value_json_subset" in scenario.expect:
            _matches_subset(
                result["value"],
                scenario.expect["value_json_subset"],
                "driver.value",
                failures,
            )
    elif actual_outcome == "error":
        if result["value"] is not None:
            failures.append(f"error driver result has non-null value: {result['value']!r}")
        error = result["error"]
        if not isinstance(error, dict):
            failures.append(f"error driver result has malformed error: {error!r}")
        else:
            for field in ("type", "message"):
                if not isinstance(error.get(field), str) or not error[field]:
                    failures.append(f"driver error.{field} must be a non-empty string")
            expected_status = scenario.expect.get("error_status")
            if expected_status is not None and error.get("status_code") != expected_status:
                failures.append(
                    f"driver error.status_code expected {expected_status}, "
                    f"got {error.get('status_code')!r}"
                )
    requests = transcript.get("requests")
    if not isinstance(requests, list):
        failures.append("transcript requests is not an array")
        requests = []
    expected_attempts = scenario.expect["attempts"]
    if len(requests) != expected_attempts:
        failures.append(f"expected {expected_attempts} wire attempts, got {len(requests)}")

    for index, request in enumerate(requests):
        where = f"attempt {index}"
        if request.get("method") != scenario.operation.method:
            failures.append(
                f"{where}: method expected {scenario.operation.method}, "
                f"got {request.get('method')!r}"
            )
        expected_target = f"/v1/{scenario.operation.path.lstrip('/')}"
        if request.get("target") != expected_target:
            failures.append(
                f"{where}: target expected {expected_target!r}, got {request.get('target')!r}"
            )
        if "body_json_subset" in scenario.expect:
            _matches_subset(
                request.get("body_json"),
                scenario.expect["body_json_subset"],
                f"{where}.body_json",
                failures,
            )

    for name in scenario.expect.get("same_headers", []):
        values = [
            _one(request.get("headers", {}), name, f"attempt {index}", failures)
            for index, request in enumerate(requests)
        ]
        if len(values) > 1 and (None in values or len(set(values)) != 1):
            failures.append(
                f"header {name!r} must be present and identical on every attempt: {values}"
            )

    common_headers = scenario.expect.get("headers", {})
    if isinstance(common_headers, dict):
        for index, request in enumerate(requests):
            for name, rule in common_headers.items():
                actual = _one(request.get("headers", {}), name, f"attempt {index}", failures)
                _check_header_rule(actual, rule, name, f"attempt {index}", failures)
    else:
        failures.append("expect.headers must be an object")

    attempt_headers = scenario.expect.get("attempt_headers", [])
    if not isinstance(attempt_headers, list):
        failures.append("expect.attempt_headers must be an array")
    else:
        for index, rules in enumerate(attempt_headers):
            if index >= len(requests):
                break
            if not isinstance(rules, dict):
                failures.append(f"expect.attempt_headers[{index}] must be an object")
                continue
            for name, rule in rules.items():
                actual = _one(
                    requests[index].get("headers", {}), name, f"attempt {index}", failures
                )
                _check_header_rule(actual, rule, name, f"attempt {index}", failures)

    server_errors = transcript.get("server_errors", [])
    if server_errors:
        failures.extend(f"fault server: {error}" for error in server_errors)
    return Verification(ok=not failures, failures=tuple(failures))

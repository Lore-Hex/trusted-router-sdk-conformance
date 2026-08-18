from __future__ import annotations

from pathlib import Path

from trusted_router_conformance.oracle import verify
from trusted_router_conformance.schema import load_scenario


def _request(header: str) -> dict[str, object]:
    return {
        "method": "POST",
        "target": "/v1/chat/completions",
        "headers": {
            "idempotency-key": ["tr-conformance-telemetry"],
            "x-tr-client": [header],
        },
        "body_json": {"model": "auto", "messages": []},
    }


def test_oracle_accepts_dynamic_telemetry_counters() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "07-telemetry-retry.json")
    transcript = {
        "requests": [
            _request("v=1;a=0;s=0"),
            _request("v=1;a=1;po=http_error;pc=none;ph=apex;pm=3;sm=17;s=0;fo=0"),
        ],
        "server_errors": [],
    }
    result = {
        "protocol_version": 1,
        "sdk": "python",
        "scenario": "telemetry-retry",
        "outcome": "success",
        "value": {"ok": True},
        "error": None,
    }
    checked = verify(scenario, result, transcript)
    assert checked.ok, checked.failures


def test_oracle_reports_duplicate_and_changed_idempotency_headers() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "02-retry-503.json")
    base = {
        "method": "POST",
        "target": "/v1/chat/completions",
        "body_json": {"model": "auto", "messages": []},
    }
    transcript = {
        "requests": [
            {**base, "headers": {"idempotency-key": ["one", "duplicate"]}},
            {**base, "headers": {"idempotency-key": ["two"]}},
        ],
        "server_errors": [],
    }
    result = {
        "protocol_version": 1,
        "sdk": "python",
        "scenario": "retry-503",
        "outcome": "success",
        "value": {"ok": True},
        "error": None,
    }
    checked = verify(scenario, result, transcript)
    assert not checked.ok
    assert any("expected one" in failure for failure in checked.failures)
    assert any("identical" in failure for failure in checked.failures)


def test_oracle_requires_terminal_http_status_in_normalized_error() -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "03-verdict-false.json")
    transcript = {
        "requests": [
            {
                "method": "POST",
                "target": "/v1/chat/completions",
                "headers": {"idempotency-key": ["tr-conformance-verdict-false"]},
                "body_json": {"model": "auto", "messages": []},
            }
        ],
        "server_errors": [],
    }
    result = {
        "protocol_version": 1,
        "sdk": "python",
        "scenario": "verdict-false",
        "outcome": "error",
        "value": None,
        "error": {"type": "InternalError", "message": "wrong", "status_code": 500},
    }
    checked = verify(scenario, result, transcript, expected_sdk="python")
    assert not checked.ok
    assert any("status_code expected 503" in failure for failure in checked.failures)

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trusted_router_conformance.runner import discover_manifests, discover_scenarios
from trusted_router_conformance.schema import SchemaError, load_scenario


def test_every_committed_scenario_and_driver_loads() -> None:
    scenarios = discover_scenarios()
    manifests = discover_manifests()
    assert len(scenarios) >= 25
    assert {"python", "javascript"} <= set(manifests)
    assert all(scenario.operation.path.startswith("/") for scenario in scenarios.values())


def test_scenario_rejects_protocol_drift(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"protocol_version": 2}), encoding="utf-8")
    with pytest.raises(SchemaError, match="protocol_version"):
        load_scenario(path)


def test_scenario_rejects_multiple_body_encodings(tmp_path: Path) -> None:
    path = tmp_path / "bad-body.json"
    path.write_text(
        json.dumps(
            {
                "protocol_version": 1,
                "name": "bad",
                "description": "invalid action",
                "operation": {"method": "GET", "path": "/x"},
                "actions": [{"kind": "response", "status": 200, "json": {}, "text": "also"}],
                "expect": {"outcome": "success", "attempts": 1},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(SchemaError, match="only one response body"):
        load_scenario(path)


def _valid_scenario() -> dict[str, object]:
    return {
        "protocol_version": 1,
        "name": "strict-example",
        "description": "A valid strict scenario.",
        "requires": ["core"],
        "operation": {"method": "POST", "path": "/x", "headers": {}},
        "client": {"max_retries": 0, "timeout_ms": 1000, "telemetry": False},
        "actions": [{"kind": "response", "status": 200, "json": {}}],
        "expect": {"outcome": "success", "attempts": 1},
    }


def test_scenario_rejects_unknown_typoed_fields(tmp_path: Path) -> None:
    value = _valid_scenario()
    value["clinet"] = value.pop("client")
    path = tmp_path / "typo.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SchemaError, match="unknown fields: clinet"):
        load_scenario(path)


def test_scenario_requires_one_action_per_expected_attempt(tmp_path: Path) -> None:
    value = _valid_scenario()
    value["expect"] = {"outcome": "success", "attempts": 2}
    path = tmp_path / "attempts.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SchemaError, match="actions has 1 entries"):
        load_scenario(path)


def test_scenario_rejects_unknown_header_rule(tmp_path: Path) -> None:
    value = _valid_scenario()
    value["expect"] = {
        "outcome": "success",
        "attempts": 1,
        "headers": {"x-test": {"match": "anything"}},
    }
    path = tmp_path / "header-rule.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SchemaError, match="unknown fields: match"):
        load_scenario(path)


def test_scenario_validates_extended_entrypoint_and_timing_fields(tmp_path: Path) -> None:
    value = _valid_scenario()
    operation = value["operation"]
    assert isinstance(operation, dict)
    operation["entrypoint"] = "not-a-public-entrypoint"
    path = tmp_path / "entrypoint.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SchemaError, match="operation.entrypoint"):
        load_scenario(path)

    value = _valid_scenario()
    client = value["client"]
    assert isinstance(client, dict)
    client["cancel_after_ms"] = 0
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SchemaError, match="cancel_after_ms"):
        load_scenario(path)

    value = _valid_scenario()
    operation = value["operation"]
    assert isinstance(operation, dict)
    operation["entrypoint"] = "oauth_exchange"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SchemaError, match="requires POST /auth/keys"):
        load_scenario(path)


def test_cross_origin_redirect_requires_redirect_status(tmp_path: Path) -> None:
    value = _valid_scenario()
    value["actions"] = [{"kind": "cross_origin_redirect", "status": 200}]
    path = tmp_path / "redirect.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SchemaError, match="300..399"):
        load_scenario(path)


def test_stream_response_variant_requires_buffered_variant(tmp_path: Path) -> None:
    value = _valid_scenario()
    value["actions"] = [{"kind": "response", "status": 200, "stream_text": "data: [DONE]\n\n"}]
    path = tmp_path / "stream-variant.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SchemaError, match="requires a buffered response body variant"):
        load_scenario(path)

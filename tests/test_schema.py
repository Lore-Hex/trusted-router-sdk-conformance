from __future__ import annotations

import json
from pathlib import Path

import pytest

from trusted_router_conformance.runner import discover_manifests, discover_scenarios
from trusted_router_conformance.schema import SchemaError, load_scenario


def test_every_committed_scenario_and_driver_loads() -> None:
    scenarios = discover_scenarios()
    manifests = discover_manifests()
    assert len(scenarios) >= 11
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

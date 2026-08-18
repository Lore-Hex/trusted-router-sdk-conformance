from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from trusted_router_conformance.cli import _roots, _skip_policy_failures
from trusted_router_conformance.runner import (
    RunResult,
    _driver_env,
    _parse_driver_json,
    repository_root,
    run_one,
)
from trusted_router_conformance.schema import DriverManifest, load_scenario


def test_driver_result_must_be_final_nonempty_stdout_line() -> None:
    valid = '{"protocol_version":1,"outcome":"success"}'
    assert _parse_driver_json("build log\n" + valid + "\n") == {
        "protocol_version": 1,
        "outcome": "success",
    }
    with pytest.raises(ValueError, match="final non-empty stdout line"):
        _parse_driver_json(valid + "\nlate build log\n")


def test_sdk_root_rejects_typos_duplicates_and_unselected_sdks() -> None:
    with pytest.raises(argparse.ArgumentTypeError, match="unknown SDK 'pythno'"):
        _roots(["pythno=/tmp/x"], available={"python", "go"}, selected={"python"})
    with pytest.raises(argparse.ArgumentTypeError, match="unselected SDK 'go'"):
        _roots(["go=/tmp/x"], available={"python", "go"}, selected={"python"})
    with pytest.raises(argparse.ArgumentTypeError, match="repeats SDK 'python'"):
        _roots(
            ["python=/tmp/one", "python=/tmp/two"],
            available={"python"},
            selected={"python"},
        )


def test_skip_allowlist_is_exact() -> None:
    result = RunResult(
        sdk="python",
        scenario="known-gap",
        status="skip",
        duration_ms=0,
        failures=(),
        driver_result=None,
        transcript=None,
        stdout="",
        stderr="",
    )
    assert _skip_policy_failures([result], {"known-gap"}) == []
    assert _skip_policy_failures([result], set()) == ["unexpected skips: known-gap"]
    assert _skip_policy_failures([], {"fixed-gap"}) == ["allowed skips did not occur: fixed-gap"]


def test_driver_environment_does_not_inherit_secrets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "01-success.json")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak")
    monkeypatch.setenv("PATH", "/usr/bin")
    server = SimpleNamespace(
        logical_base_url="https://api.trustedrouter.com:1234/v1",
        physical_origin="https://127.0.0.1:1234",
        ca_cert_path=tmp_path / "ephemeral-ca.pem",
    )
    env = _driver_env(scenario, server, root)
    assert env["PATH"] == "/usr/bin"
    assert env["TR_CONFORMANCE_CA_CERT"] == str(server.ca_cert_path)
    assert env["NODE_EXTRA_CA_CERTS"] == str(server.ca_cert_path)
    assert "GITHUB_TOKEN" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env


def test_missing_driver_executable_is_a_failed_report_entry(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "01-success.json")
    manifest = DriverManifest(
        sdk="missing-executable",
        command=("trusted-router-conformance-command-that-does-not-exist",),
        capabilities=frozenset(scenario.requires),
        root_name="unused",
        path=root / "drivers" / "missing-executable" / "driver.json",
    )

    result = run_one(manifest, scenario, sdk_root=tmp_path, repo=root)

    assert result.status == "fail"
    assert result.driver_result is None
    assert result.transcript is not None
    assert result.transcript["requests"] == []
    assert result.stdout == ""
    assert result.stderr == ""
    assert len(result.failures) == 1
    assert result.failures[0].startswith("driver process could not be started: FileNotFoundError:")
    assert json.loads(json.dumps(result.as_dict()))["status"] == "fail"


def test_invalid_driver_command_template_is_a_failed_result(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    scenario = load_scenario(root / "scenarios" / "01-success.json")
    manifest = DriverManifest(
        sdk="bad-template",
        command=("{unsupported_placeholder}",),
        capabilities=frozenset(scenario.requires),
        root_name="unused",
        path=root / "drivers" / "bad-template" / "driver.json",
    )

    result = run_one(manifest, scenario, sdk_root=tmp_path, repo=root)

    assert result.status == "fail"
    assert result.driver_result is None
    assert result.transcript is not None
    assert result.transcript["requests"] == []
    assert result.failures == ("invalid driver command template: 'unsupported_placeholder'",)


def test_repository_root_falls_back_to_packaged_assets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "site-packages" / "trusted_router_conformance"
    packaged_root = package / "_data"
    (packaged_root / "drivers").mkdir(parents=True)
    (packaged_root / "scenarios").mkdir()
    monkeypatch.setattr(
        "trusted_router_conformance.paths.__file__",
        str(package / "paths.py"),
    )

    assert repository_root() == packaged_root

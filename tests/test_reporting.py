from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from trusted_router_conformance.cli import main
from trusted_router_conformance.reporting import (
    _git_identity,
    _probe_toolchain,
    collect_report_metadata,
)
from trusted_router_conformance.runner import RunResult


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_git_identity_records_sha_and_dirty_state(tmp_path: Path) -> None:
    repo = tmp_path / "sdk"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.name", "Conformance Test")
    _git(repo, "config", "user.email", "conformance@example.invalid")
    tracked = repo / "tracked.txt"
    tracked.write_text("initial\n", encoding="utf-8")
    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "-m", "initial")

    clean = _git_identity(repo)
    assert clean["is_repository"] is True
    assert isinstance(clean["sha"], str) and len(clean["sha"]) == 40
    assert clean["dirty"] is False

    tracked.write_text("changed\n", encoding="utf-8")
    assert _git_identity(repo)["dirty"] is True


def test_missing_toolchain_is_reported_without_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    assert _probe_toolchain(("not-installed", "--version")) == {
        "available": False,
        "path": None,
        "version": None,
    }


def test_report_metadata_is_json_serializable_and_names_selected_sdks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = tmp_path / "harness"
    python_sdk = tmp_path / "python-sdk"
    harness.mkdir()
    python_sdk.mkdir()
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    metadata = collect_report_metadata(
        harness_root=harness,
        sdk_roots={"python": python_sdk, "missing": tmp_path / "missing-sdk"},
    )

    assert datetime.fromisoformat(metadata["generated_at_utc"].replace("Z", "+00:00"))
    assert metadata["harness"]["path"] == str(harness.resolve())
    assert metadata["sdks"]["python"]["exists"] is True
    assert metadata["sdks"]["missing"]["exists"] is False
    assert set(metadata["sdks"]) == {"missing", "python"}
    assert all(
        tool["available"] is False for tool in metadata["environment"]["toolchains"].values()
    )
    json.dumps(metadata)


def test_cli_embeds_metadata_in_json_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdk_root = tmp_path / "python-sdk"
    sdk_root.mkdir()
    report_path = tmp_path / "report.json"
    captured_roots: dict[str, Path] = {}

    def fake_run_matrix(*_args: object, **kwargs: object) -> list[object]:
        captured_roots.update(kwargs["sdk_roots"])  # type: ignore[arg-type]
        return []

    monkeypatch.setattr("trusted_router_conformance.cli.run_matrix", fake_run_matrix)
    monkeypatch.setattr(
        "trusted_router_conformance.cli.collect_report_metadata",
        lambda **_kwargs: {"sentinel": True},
    )

    exit_code = main(
        [
            "--sdk",
            "python",
            "--scenario",
            "success",
            "--sdk-root",
            f"python={sdk_root}",
            "--json-report",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert report["metadata"] == {"sentinel": True}
    assert captured_roots == {"python": sdk_root.resolve()}


def test_cli_json_report_surfaces_beacons(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sdk_root = tmp_path / "python-sdk"
    sdk_root.mkdir()
    report_path = tmp_path / "report.json"
    beacon = {
        "path": "/v1/client-events",
        "byte_length": 2,
        "json_parsed": True,
        "schema_version": None,
        "events_count": 0,
        "counters_count": 0,
        "top_level_keys_recognized": True,
    }
    run_result = RunResult(
        sdk="python",
        scenario="success",
        status="pass",
        duration_ms=1,
        failures=(),
        driver_result={"outcome": "success"},
        transcript={"requests": [], "beacons": [beacon], "server_errors": []},
        stdout="",
        stderr="",
    )
    monkeypatch.setattr(
        "trusted_router_conformance.cli.run_matrix", lambda *_args, **_kwargs: [run_result]
    )
    monkeypatch.setattr(
        "trusted_router_conformance.cli.collect_report_metadata", lambda **_kwargs: {}
    )

    exit_code = main(
        [
            "--sdk",
            "python",
            "--scenario",
            "success",
            "--sdk-root",
            f"python={sdk_root}",
            "--json-report",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert report["results"][0]["transcript"]["beacons"] == [beacon]

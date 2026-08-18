#!/usr/bin/env python3
"""Compile the Go adapter against the SDK checkout selected by the runner."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _has_result(stdout: str) -> bool:
    for line in stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "outcome" in value:
            return True
    return False


def _fallback(message: str) -> None:
    result = {
        "protocol_version": 1,
        "sdk": "go",
        "scenario": os.environ.get("TR_CONFORMANCE_SCENARIO", "unknown"),
        "outcome": "error",
        "value": None,
        "error": {"type": "DriverExecutionError", "message": message},
    }
    print(json.dumps(result, separators=(",", ":"), ensure_ascii=False), flush=True)


def main() -> int:
    driver_dir = Path(__file__).resolve().parent
    sdk_value = os.environ.get("TR_CONFORMANCE_SDK_ROOT")
    if sdk_value is None:
        _fallback("missing TR_CONFORMANCE_SDK_ROOT")
        return 1
    sdk_root = Path(sdk_value).resolve()
    if not (sdk_root / "go.mod").is_file():
        _fallback(f"Go SDK root has no go.mod: {sdk_root}")
        return 1

    with tempfile.TemporaryDirectory(prefix="tr-conformance-go-") as temporary:
        project = Path(temporary)
        shutil.copyfile(driver_dir / "main.go", project / "main.go")
        (project / "go.mod").write_text(
            "module trusted-router-conformance-driver\n\n"
            "go 1.23\n\n"
            "require github.com/Lore-Hex/trusted-router-go v0.0.0\n\n"
            "replace github.com/Lore-Hex/trusted-router-go => "
            f"{json.dumps(str(sdk_root), ensure_ascii=False)}\n",
            encoding="utf-8",
        )

        environment = dict(os.environ)
        environment.update(
            {
                "ALL_PROXY": "",
                "GONOSUMDB": "",
                "GOPROXY": "direct",
                "GOSUMDB": "sum.golang.org",
                "GOWORK": "off",
                "HTTP_PROXY": "",
                "HTTPS_PROXY": "",
                "NO_PROXY": "*",
                "all_proxy": "",
                "http_proxy": "",
                "https_proxy": "",
                "no_proxy": "*",
            }
        )
        completed = subprocess.run(
            ["go", "run", "-mod=mod", "."],
            cwd=project,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    if completed.stdout:
        sys.stdout.write(completed.stdout)
        sys.stdout.flush()
    if completed.stderr:
        sys.stderr.write(completed.stderr)
        sys.stderr.flush()
    if completed.returncode != 0 and not _has_result(completed.stdout):
        _fallback(f"go run exited with status {completed.returncode}")
        return completed.returncode
    return completed.returncode


if __name__ == "__main__":
    try:
        exit_code = main()
    except BaseException as error:
        _fallback(f"{type(error).__name__}: {error}")
        exit_code = 1
    raise SystemExit(exit_code)

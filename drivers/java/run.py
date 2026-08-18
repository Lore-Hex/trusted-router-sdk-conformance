#!/usr/bin/env python3
"""Build and run the Java adapter using the selected SDK checkout's wrapper."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SDK = "java"


def _scenario() -> str:
    return os.environ.get("TR_CONFORMANCE_SCENARIO", os.environ.get("SCENARIO", "unknown"))


def _failure(error_type: str, message: str) -> dict[str, Any]:
    return {
        "protocol_version": 1,
        "sdk": SDK,
        "scenario": _scenario(),
        "outcome": "error",
        "value": None,
        "error": {"type": error_type, "message": message},
    }


def _emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, separators=(",", ":")))


def _driver_result(stdout: str) -> dict[str, Any] | None:
    for line in reversed(stdout.splitlines()):
        try:
            candidate = json.loads(line.strip())
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(candidate, dict) and candidate.get("outcome") in {"success", "error"}:
            return candidate
    return None


def _working_java(java_home: Path | None) -> bool:
    executable = java_home / "bin" / "java" if java_home is not None else None
    if executable is None or not executable.is_file():
        return False
    try:
        return (
            subprocess.run(
                [str(executable), "-version"],
                capture_output=True,
                timeout=5,
                check=False,
            ).returncode
            == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


def _java_environment() -> dict[str, str]:
    """Use an inherited JDK, with narrow macOS/Homebrew fallbacks.

    Homebrew intentionally does not register its keg-only JDK with macOS, so
    `/usr/bin/java` can be a failing system stub even though JDK 17 is present.
    The driver should still be runnable from the core harness without requiring
    a machine-specific JAVA_HOME export.
    """
    env = dict(os.environ)
    candidates: list[Path] = []
    inherited = env.get("JAVA_HOME")
    if inherited:
        candidates.append(Path(inherited))
    on_path = shutil.which("java")
    if on_path:
        candidates.append(Path(on_path).resolve().parent.parent)
    java_home_helper = Path("/usr/libexec/java_home")
    if java_home_helper.is_file():
        try:
            resolved = subprocess.run(
                [str(java_home_helper), "-v", "17"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if resolved.returncode == 0 and resolved.stdout.strip():
                candidates.append(Path(resolved.stdout.strip()))
        except (OSError, subprocess.TimeoutExpired):
            pass
    candidates.extend(
        [
            Path("/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home"),
            Path("/usr/local/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home"),
            Path("/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home"),
            Path("/usr/local/opt/openjdk/libexec/openjdk.jdk/Contents/Home"),
        ]
    )
    for candidate in candidates:
        if _working_java(candidate):
            env["JAVA_HOME"] = str(candidate)
            env["PATH"] = str(candidate / "bin") + os.pathsep + env.get("PATH", "")
            break
    return env


def main() -> int:
    driver_root = Path(__file__).resolve().parent
    raw_sdk_root = os.environ.get("TR_CONFORMANCE_SDK_ROOT")
    if not raw_sdk_root:
        _emit(_failure("DriverConfigurationError", "TR_CONFORMANCE_SDK_ROOT is required"))
        return 2
    sdk_root = Path(raw_sdk_root).expanduser().resolve()
    if not sdk_root.is_dir():
        _emit(_failure("DriverConfigurationError", f"SDK root does not exist: {sdk_root}"))
        return 2

    wrapper = sdk_root / ("gradlew.bat" if os.name == "nt" else "gradlew")
    if not wrapper.is_file():
        _emit(_failure("DriverConfigurationError", f"Gradle wrapper not found: {wrapper}"))
        return 2

    cache_key = hashlib.sha256(str(sdk_root).encode("utf-8")).hexdigest()[:16]
    cache_root = Path(tempfile.gettempdir()) / "trusted-router-conformance-java" / cache_key
    project_cache = cache_root / "project-cache"
    build_dir = cache_root / "build"
    project_cache.mkdir(parents=True, exist_ok=True)
    build_dir.mkdir(parents=True, exist_ok=True)

    command = [
        str(wrapper),
        "--console=plain",
        "--quiet",
        "--project-dir",
        str(driver_root),
        "--project-cache-dir",
        str(project_cache),
        f"-PtrConformanceBuildDir={build_dir}",
        "run",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=sdk_root,
            env=_java_environment(),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        _emit(_failure(type(exc).__name__, str(exc)))
        return 2

    result = _driver_result(completed.stdout)
    if result is None:
        detail = (completed.stderr or completed.stdout).strip()
        if len(detail) > 4_000:
            detail = detail[-4_000:]
        if not detail:
            detail = f"Gradle driver exited with status {completed.returncode} without a result"
        _emit(_failure("DriverBuildError", detail))
        return completed.returncode or 2

    # Gradle can write lifecycle diagnostics even in quiet mode. Only forward
    # the adapter's protocol object so stdout always contains exactly one JSON
    # result line.
    _emit(result)
    if completed.returncode != 0:
        return completed.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())

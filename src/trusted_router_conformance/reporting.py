"""Best-effort provenance metadata for machine-readable conformance reports."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PROBE_TIMEOUT_SECONDS = 5.0
_MAX_VERSION_LENGTH = 4096
_TOOLCHAIN_COMMANDS: dict[str, tuple[str, ...]] = {
    "git": ("git", "--version"),
    "node": ("node", "--version"),
    "npm": ("npm", "--version"),
    "go": ("go", "version"),
    "rustc": ("rustc", "--version"),
    "cargo": ("cargo", "--version"),
    "java": ("java", "-version"),
    "javac": ("javac", "-version"),
    "swift": ("swift", "--version"),
}


def _probe_environment() -> dict[str, str]:
    """Return only non-secret environment needed by local version probes."""

    allowed = {
        "APPDATA",
        "COMSPEC",
        "DEVELOPER_DIR",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "JAVA_HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "SDKROOT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
    return {
        name: value
        for name, value in os.environ.items()
        if name.upper() in allowed or name.upper().startswith("LC_")
    }


def _capture(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str] | None:
    executable = shutil.which(command[0])
    if executable is None:
        return None
    try:
        return subprocess.run(
            [executable, *command[1:]],
            cwd=cwd,
            env=_probe_environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _version_text(completed: subprocess.CompletedProcess[str] | None) -> str | None:
    if completed is None or completed.returncode != 0:
        return None
    value = " ".join((completed.stdout.strip() or completed.stderr.strip()).split())
    return value[:_MAX_VERSION_LENGTH] or None


def _probe_toolchain(command: tuple[str, ...]) -> dict[str, Any]:
    executable = shutil.which(command[0])
    if executable is None:
        return {"available": False, "path": None, "version": None}
    completed = _capture(command)
    return {
        "available": completed is not None and completed.returncode == 0,
        "path": executable,
        "version": _version_text(completed),
    }


def _git_identity(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    empty = {"is_repository": None, "sha": None, "dirty": None}
    if not resolved.is_dir():
        return empty

    top_level = _capture(
        ("git", "-c", "core.fsmonitor=false", "-C", str(resolved), "rev-parse", "--show-toplevel")
    )
    if top_level is None:
        return empty
    if top_level.returncode != 0:
        return {"is_repository": False, "sha": None, "dirty": None}
    try:
        reported_root = Path(top_level.stdout.strip()).resolve()
    except (OSError, RuntimeError):
        return {"is_repository": False, "sha": None, "dirty": None}
    if reported_root != resolved:
        return {"is_repository": False, "sha": None, "dirty": None}

    sha_result = _capture(
        (
            "git",
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(resolved),
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        )
    )
    sha = None
    if sha_result is not None and sha_result.returncode == 0:
        sha = sha_result.stdout.strip() or None

    status_result = _capture(
        (
            "git",
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(resolved),
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
        )
    )
    dirty = None
    if status_result is not None and status_result.returncode == 0:
        dirty = bool(status_result.stdout)
    return {"is_repository": True, "sha": sha, "dirty": dirty}


def _checkout_identity(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "exists": resolved.is_dir(),
        "git": _git_identity(resolved),
    }


def collect_report_metadata(
    *,
    harness_root: Path,
    sdk_roots: Mapping[str, Path],
) -> dict[str, Any]:
    """Collect reproducibility data without making probe failures fatal."""

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "generated_at_utc": generated_at,
        "harness": _checkout_identity(harness_root),
        "sdks": {sdk: _checkout_identity(path) for sdk, path in sorted(sdk_roots.items())},
        "environment": {
            "os": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "platform": platform.platform(),
            },
            "python": {
                "implementation": platform.python_implementation(),
                "version": platform.python_version(),
                "executable": sys.executable,
            },
            "toolchains": {
                name: _probe_toolchain(command) for name, command in _TOOLCHAIN_COMMANDS.items()
            },
        },
    }

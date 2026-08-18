#!/usr/bin/env python3
"""Compile the Rust adapter against the SDK checkout selected by the runner."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _cargo_manifest(sdk_root: Path) -> str:
    crate_path = json.dumps(str(sdk_root / "crates" / "trusted-router"), ensure_ascii=False)
    return f"""\
[package]
name = "trusted-router-conformance-driver"
version = "0.0.0"
edition = "2021"
rust-version = "1.88"
publish = false

[dependencies]
futures-util = "0.3.31"
http = "1.3.1"
serde_json = "1.0.140"
tokio = {{ version = "1.44.2", features = ["macros", "rt-multi-thread", "time"] }}
trusted-router = {{ path = {crate_path}, default-features = false }}
url = "2.5.4"
"""


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
        "sdk": "rust",
        "scenario": os.environ.get("TR_CONFORMANCE_SCENARIO", "unknown"),
        "outcome": "error",
        "value": None,
        "error": {"type": "DriverExecutionError", "message": message},
    }
    print(json.dumps(result, separators=(",", ":"), ensure_ascii=False), flush=True)


def _project(driver_dir: Path, sdk_root: Path) -> tuple[Path, str, bool]:
    lockfile = sdk_root / "Cargo.lock"
    if not lockfile.is_file():
        raise RuntimeError(f"Rust SDK root has no Cargo.lock: {sdk_root}")
    workspace_manifest = sdk_root / "Cargo.toml"
    crate_manifest = sdk_root / "crates" / "trusted-router" / "Cargo.toml"
    manifest = _cargo_manifest(sdk_root)
    main_source = (driver_dir / "main.rs").read_bytes()
    cache_key = hashlib.sha256(str(sdk_root).encode()).hexdigest()[:20]
    project = Path(tempfile.gettempdir()) / f"tr-conformance-rust-{cache_key}"
    (project / "src").mkdir(parents=True, exist_ok=True)
    (project / "Cargo.toml").write_text(manifest, encoding="utf-8")
    (project / "src" / "main.rs").write_bytes(main_source)

    lock_input = hashlib.sha256()
    for value in (
        lockfile.read_bytes(),
        workspace_manifest.read_bytes(),
        crate_manifest.read_bytes(),
        manifest.encode(),
    ):
        lock_input.update(value)
        lock_input.update(b"\0")
    lock_stamp = lock_input.hexdigest()
    stamp_path = project / ".driver-lock-input"
    try:
        previous_stamp = stamp_path.read_text(encoding="utf-8").strip()
    except OSError:
        previous_stamp = ""
    needs_lock_update = previous_stamp != lock_stamp or not (project / "Cargo.lock").is_file()
    if needs_lock_update:
        shutil.copyfile(lockfile, project / "Cargo.lock")
    return project, lock_stamp, needs_lock_update


def main() -> int:
    sdk_value = os.environ.get("TR_CONFORMANCE_SDK_ROOT")
    if sdk_value is None:
        _fallback("missing TR_CONFORMANCE_SDK_ROOT")
        return 1
    sdk_root = Path(sdk_value).resolve()
    if not (sdk_root / "crates" / "trusted-router" / "Cargo.toml").is_file():
        _fallback(f"Rust SDK root has no trusted-router crate: {sdk_root}")
        return 1

    project, lock_stamp, needs_lock_update = _project(Path(__file__).resolve().parent, sdk_root)
    environment = dict(os.environ)
    environment.pop("CARGO_NET_OFFLINE", None)
    environment.update(
        {
            "ALL_PROXY": "",
            "CARGO_TERM_COLOR": "never",
            "CARGO_TARGET_DIR": str(project / "target"),
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "NO_PROXY": "*",
            "all_proxy": "",
            "http_proxy": "",
            "https_proxy": "",
            "no_proxy": "*",
        }
    )
    if needs_lock_update:
        prepared = subprocess.run(
            ["cargo", "metadata", "--format-version=1"],
            cwd=project,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if prepared.returncode != 0:
            if prepared.stderr:
                sys.stderr.write(prepared.stderr)
                sys.stderr.flush()
            _fallback(f"cargo metadata exited with status {prepared.returncode}")
            return prepared.returncode
        (project / ".driver-lock-input").write_text(lock_stamp + "\n", encoding="utf-8")

    completed = subprocess.run(
        ["cargo", "run", "--locked", "--quiet"],
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
        _fallback(f"cargo run exited with status {completed.returncode}")
        return completed.returncode
    return completed.returncode


if __name__ == "__main__":
    try:
        exit_code = main()
    except BaseException as error:
        _fallback(f"{type(error).__name__}: {error}")
        exit_code = 1
    raise SystemExit(exit_code)

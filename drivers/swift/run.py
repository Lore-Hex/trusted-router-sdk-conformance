#!/usr/bin/env python3
"""Build and run the Swift conformance adapter against a selected SDK checkout."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

DRIVER_DIR = Path(__file__).resolve().parent


def _error_result(message: str) -> dict[str, Any]:
    return {
        "protocol_version": 1,
        "sdk": "swift",
        "scenario": os.environ.get("TR_CONFORMANCE_SCENARIO", "unknown"),
        "outcome": "error",
        "value": None,
        "error": {"type": "SwiftDriverError", "message": message},
    }


def _write_if_changed(path: Path, contents: str) -> None:
    if path.exists() and path.read_text(encoding="utf-8") == contents:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def _swift_string(value: str) -> str:
    """Encode a Python string as a Swift string literal."""
    return json.dumps(value, ensure_ascii=False)


def _last_result(stdout: str) -> dict[str, Any] | None:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        return None
    try:
        value = json.loads(lines[-1])
    except json.JSONDecodeError:
        return None
    if isinstance(value, dict) and "outcome" in value:
        return value
    return None


def main() -> int:
    sdk_root_raw = os.environ.get("TR_CONFORMANCE_SDK_ROOT")
    if not sdk_root_raw:
        print(json.dumps(_error_result("missing TR_CONFORMANCE_SDK_ROOT"), separators=(",", ":")))
        return 2

    sdk_root = Path(sdk_root_raw).resolve()
    if not (sdk_root / "Package.swift").is_file():
        print(
            json.dumps(
                _error_result(f"Swift SDK Package.swift not found under {sdk_root}"),
                separators=(",", ":"),
            )
        )
        return 2

    ca_cert_raw = os.environ.get("TR_CONFORMANCE_CA_CERT")
    if not ca_cert_raw or not Path(ca_cert_raw).is_file():
        print(
            json.dumps(
                _error_result("TR_CONFORMANCE_CA_CERT must name a readable certificate"),
                separators=(",", ":"),
            )
        )
        return 2

    cache_key = hashlib.sha256(str(sdk_root).encode("utf-8")).hexdigest()[:16]
    package_root = (
        Path(tempfile.gettempdir()) / "trusted-router-sdk-conformance" / f"swift-{cache_key}"
    )
    manifest = f"""// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "TrustedRouterConformanceSwiftDriver",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(name: "TrustedRouterSDK", path: {_swift_string(str(sdk_root))})
    ],
    targets: [
        .executableTarget(
            name: "TrustedRouterConformanceSwiftDriver",
            dependencies: [
                .product(name: "TrustedRouter", package: "TrustedRouterSDK")
            ]
        )
    ]
)
"""
    _write_if_changed(package_root / "Package.swift", manifest)
    source_root = package_root / "Sources" / "TrustedRouterConformanceSwiftDriver"
    # A source file literally named main.swift is treated as a top-level-code
    # entry point by Swift. Give the generated copy a neutral name so its
    # async @main declaration is the package's sole entry point.
    legacy_main = source_root / "main.swift"
    if legacy_main.exists():
        legacy_main.unlink()
    _write_if_changed(
        source_root / "DriverMain.swift",
        (DRIVER_DIR / "main.swift").read_text(encoding="utf-8"),
    )

    module_cache = package_root / ".module-cache"
    module_cache.mkdir(parents=True, exist_ok=True)

    completed = subprocess.run(
        [
            "swift",
            "run",
            "--package-path",
            str(package_root),
            "TrustedRouterConformanceSwiftDriver",
        ],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            # FoundationNetworking uses libcurl on Linux. These variables
            # make this run's ephemeral test CA its exact trust bundle;
            # Darwin uses the exact SecTrust anchor in DriverMain instead.
            "SSL_CERT_FILE": ca_cert_raw,
            "CURL_CA_BUNDLE": ca_cert_raw,
            # Keep compiler caches beside the generated package. This avoids
            # depending on a writable developer home directory in CI/sandboxes.
            "CLANG_MODULE_CACHE_PATH": str(module_cache),
            "SWIFTPM_MODULECACHE_OVERRIDE": str(module_cache),
        },
    )
    if completed.stderr:
        sys.stderr.write(completed.stderr)

    result = _last_result(completed.stdout)
    missing_result = result is None
    if result is None:
        detail = completed.stderr.strip() or completed.stdout.strip()
        if not detail:
            detail = f"swift run exited with status {completed.returncode}"
        result = _error_result(detail[-4000:])
    print(json.dumps(result, separators=(",", ":"), ensure_ascii=False), flush=True)
    if completed.returncode != 0:
        return completed.returncode
    return 2 if missing_result else 0


if __name__ == "__main__":
    raise SystemExit(main())

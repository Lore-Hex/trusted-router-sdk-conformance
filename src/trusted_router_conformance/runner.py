"""Driver discovery and isolated scenario execution."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trusted_router_conformance.oracle import Verification, verify
from trusted_router_conformance.paths import repository_root
from trusted_router_conformance.schema import (
    DriverManifest,
    Scenario,
    load_driver_manifest,
    load_scenario,
)
from trusted_router_conformance.server import FaultServer

_SAFE_ENVIRONMENT_NAMES = {
    "APPDATA",
    "CARGO_HOME",
    "CI",
    "CLANG_MODULE_CACHE_PATH",
    "COMSPEC",
    "DEVELOPER_DIR",
    "DYLD_LIBRARY_PATH",
    "GITHUB_ACTIONS",
    "GOCACHE",
    "GOMODCACHE",
    "GOPATH",
    "GOROOT",
    "GRADLE_USER_HOME",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "JAVA_HOME",
    "LANG",
    "LD_LIBRARY_PATH",
    "LIBRARY_PATH",
    "LOCALAPPDATA",
    "LOGNAME",
    "NUMBER_OF_PROCESSORS",
    "PATH",
    "PATHEXT",
    "PKG_CONFIG_PATH",
    "PROCESSOR_ARCHITECTURE",
    "RUNNER_ARCH",
    "RUNNER_OS",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "SDKROOT",
    "SHELL",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "USER",
    "USERPROFILE",
    "UV_CACHE_DIR",
    "WINDIR",
    "XDG_CACHE_HOME",
}


@dataclass(frozen=True)
class RunResult:
    sdk: str
    scenario: str
    status: str
    duration_ms: int
    failures: tuple[str, ...]
    driver_result: dict[str, Any] | None
    transcript: dict[str, Any] | None
    stdout: str
    stderr: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "sdk": self.sdk,
            "scenario": self.scenario,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "failures": list(self.failures),
            "driver_result": self.driver_result,
            "transcript": self.transcript,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def discover_manifests(root: Path | None = None) -> dict[str, DriverManifest]:
    repo = (root or repository_root()).resolve()
    manifests: dict[str, DriverManifest] = {}
    for path in sorted((repo / "drivers").glob("*/driver.json")):
        manifest = load_driver_manifest(path)
        if manifest.sdk in manifests:
            raise ValueError(f"duplicate driver manifest for {manifest.sdk!r}")
        manifests[manifest.sdk] = manifest
    return manifests


def discover_scenarios(root: Path | None = None) -> dict[str, Scenario]:
    repo = (root or repository_root()).resolve()
    scenarios: dict[str, Scenario] = {}
    for path in sorted((repo / "scenarios").glob("*.json")):
        scenario = load_scenario(path)
        if scenario.name in scenarios:
            raise ValueError(f"duplicate scenario name {scenario.name!r}")
        scenarios[scenario.name] = scenario
    return scenarios


def _parse_driver_json(stdout: str) -> dict[str, Any]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise ValueError("driver printed no non-empty stdout line")
    try:
        value = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise ValueError("driver's final non-empty stdout line is not JSON") from exc
    if not isinstance(value, dict) or "outcome" not in value:
        raise ValueError("driver's final JSON value is not a result object")
    return value


def _driver_env(
    scenario: Scenario,
    server: FaultServer,
    sdk_root: Path,
) -> dict[str, str]:
    # Do not hand arbitrary CI/developer credentials to six third-party build
    # processes. Native tools receive paths, caches, locale, and toolchain
    # selectors only; scenario values are added explicitly below.
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in _SAFE_ENVIRONMENT_NAMES or key.upper().startswith("LC_")
    }
    ca_cert = server.ca_cert_path
    env.update(
        {
            "TR_CONFORMANCE_PROTOCOL_VERSION": "1",
            "TR_CONFORMANCE_SCENARIO": scenario.name,
            "TR_CONFORMANCE_SDK_ROOT": str(sdk_root),
            "TR_CONFORMANCE_LOGICAL_BASE_URL": server.logical_base_url,
            "TR_CONFORMANCE_PHYSICAL_ORIGIN": server.physical_origin,
            "TR_CONFORMANCE_METHOD": scenario.operation.method,
            "TR_CONFORMANCE_ENTRYPOINT": scenario.operation.entrypoint,
            "TR_CONFORMANCE_PATH": scenario.operation.path,
            "TR_CONFORMANCE_BODY_JSON": json.dumps(
                scenario.operation.body, separators=(",", ":"), ensure_ascii=False
            ),
            "TR_CONFORMANCE_HEADERS_JSON": json.dumps(
                scenario.operation.headers, separators=(",", ":"), ensure_ascii=False
            ),
            "TR_CONFORMANCE_IDEMPOTENCY_KEY": scenario.operation.idempotency_key or "",
            "TR_CONFORMANCE_MAX_RETRIES": str(scenario.client.max_retries),
            "TR_CONFORMANCE_TIMEOUT_MS": str(scenario.client.timeout_ms),
            "TR_CONFORMANCE_TELEMETRY": "1" if scenario.client.telemetry else "0",
            "TR_CONFORMANCE_CANCEL_AFTER_MS": (
                str(scenario.client.cancel_after_ms)
                if scenario.client.cancel_after_ms is not None
                else ""
            ),
            "TR_CONFORMANCE_DEFAULT_HEADERS_JSON": json.dumps(
                scenario.client.default_headers,
                separators=(",", ":"),
                ensure_ascii=False,
            ),
            "TR_CONFORMANCE_CA_CERT": str(ca_cert),
            # Node reads additional roots only during process initialization.
            "NODE_EXTRA_CA_CERTS": str(ca_cert),
            # A process-global proxy inherited from a developer shell would route the
            # intentionally fake public hostname away from the adapter's local socket.
            "NO_PROXY": "*",
            "no_proxy": "*",
        }
    )
    return env


def _run_driver_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    process_kwargs: dict[str, Any] = {}
    if os.name == "nt":
        process_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        process_kwargs["start_new_session"] = True
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **process_kwargs,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except OSError:
                process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(
            exc.cmd,
            exc.timeout,
            output=stdout,
            stderr=stderr,
        ) from exc
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _format_command(manifest: DriverManifest, repo: Path, sdk_root: Path) -> list[str]:
    values = {
        "repo": str(repo),
        "sdk_root": str(sdk_root),
        "python": sys.executable,
    }
    return [part.format(**values) for part in manifest.command]


def run_one(
    manifest: DriverManifest,
    scenario: Scenario,
    *,
    sdk_root: Path,
    repo: Path | None = None,
    strict_capabilities: bool = False,
    process_timeout_seconds: float = 300,
) -> RunResult:
    harness_root = (repo or repository_root()).resolve()
    missing = sorted(set(scenario.requires) - manifest.capabilities)
    if missing:
        status = "fail" if strict_capabilities else "skip"
        return RunResult(
            sdk=manifest.sdk,
            scenario=scenario.name,
            status=status,
            duration_ms=0,
            failures=(f"driver lacks required capabilities: {', '.join(missing)}",),
            driver_result=None,
            transcript=None,
            stdout="",
            stderr="",
        )
    if not sdk_root.is_dir():
        return RunResult(
            sdk=manifest.sdk,
            scenario=scenario.name,
            status="fail",
            duration_ms=0,
            failures=(f"SDK root does not exist: {sdk_root}",),
            driver_result=None,
            transcript=None,
            stdout="",
            stderr="",
        )

    started = time.monotonic()
    stdout = ""
    stderr = ""
    driver_result: dict[str, Any] | None = None
    transcript: dict[str, Any] | None = None
    verification = Verification(ok=False, failures=("driver was not executed",))
    with FaultServer(scenario) as server:
        try:
            try:
                command = _format_command(manifest, harness_root, sdk_root)
            except (IndexError, KeyError, ValueError) as exc:
                verification = Verification(
                    ok=False,
                    failures=(f"invalid driver command template: {exc}",),
                )
            else:
                completed = _run_driver_process(
                    command,
                    cwd=harness_root,
                    env=_driver_env(scenario, server, sdk_root),
                    timeout=process_timeout_seconds,
                )
                stdout = completed.stdout
                stderr = completed.stderr
                try:
                    driver_result = _parse_driver_json(stdout)
                except ValueError as exc:
                    failures = [str(exc)]
                    if completed.returncode != 0:
                        failures.append(f"driver exited with status {completed.returncode}")
                    verification = Verification(ok=False, failures=tuple(failures))
                else:
                    transcript = server.transcript()
                    verification = verify(
                        scenario,
                        driver_result,
                        transcript,
                        expected_sdk=manifest.sdk,
                    )
                    if completed.returncode != 0:
                        verification = Verification(
                            ok=False,
                            failures=verification.failures
                            + (f"driver exited with status {completed.returncode}",),
                        )
        except OSError as exc:
            verification = Verification(
                ok=False,
                failures=(f"driver process could not be started: {type(exc).__name__}: {exc}",),
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            verification = Verification(
                ok=False,
                failures=(f"driver exceeded {process_timeout_seconds:g}s process timeout",),
            )
        if transcript is None:
            transcript = server.transcript()
    duration_ms = round((time.monotonic() - started) * 1000)
    return RunResult(
        sdk=manifest.sdk,
        scenario=scenario.name,
        status="pass" if verification.ok else "fail",
        duration_ms=duration_ms,
        failures=verification.failures,
        driver_result=driver_result,
        transcript=transcript,
        stdout=stdout,
        stderr=stderr,
    )


def run_matrix(
    manifests: Iterable[DriverManifest],
    scenarios: Iterable[Scenario],
    *,
    sdk_roots: dict[str, Path],
    strict_capabilities: bool = False,
    fail_fast: bool = False,
    process_timeout_seconds: float = 300,
) -> list[RunResult]:
    repo = repository_root()
    results: list[RunResult] = []
    for manifest in manifests:
        sdk_root = sdk_roots.get(manifest.sdk, repo.parent / manifest.root_name).resolve()
        for scenario in scenarios:
            result = run_one(
                manifest,
                scenario,
                sdk_root=sdk_root,
                repo=repo,
                strict_capabilities=strict_capabilities,
                process_timeout_seconds=process_timeout_seconds,
            )
            results.append(result)
            if fail_fast and result.status == "fail":
                return results
    return results

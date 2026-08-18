"""Command-line interface for the conformance matrix."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TypeVar

from trusted_router_conformance.reporting import collect_report_metadata
from trusted_router_conformance.runner import (
    RunResult,
    discover_manifests,
    discover_scenarios,
    repository_root,
    run_matrix,
)


def _csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _roots(values: list[str], *, available: set[str], selected: set[str]) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise argparse.ArgumentTypeError("--sdk-root must have SDK=PATH form")
        sdk, raw_path = value.split("=", 1)
        if not sdk or not raw_path:
            raise argparse.ArgumentTypeError("--sdk-root must have SDK=PATH form")
        if sdk not in available:
            raise argparse.ArgumentTypeError(f"--sdk-root names unknown SDK {sdk!r}")
        if sdk not in selected:
            raise argparse.ArgumentTypeError(
                f"--sdk-root names unselected SDK {sdk!r}; include it in --sdk"
            )
        if sdk in roots:
            raise argparse.ArgumentTypeError(f"--sdk-root repeats SDK {sdk!r}")
        roots[sdk] = Path(raw_path).expanduser()
    return roots


T = TypeVar("T")


def _select(available: dict[str, T], requested: list[str], noun: str) -> list[T]:
    if not requested or requested == ["all"]:
        return list(available.values())
    unknown = sorted(set(requested) - set(available))
    if unknown:
        raise ValueError(
            f"unknown {noun}{'s' if len(unknown) > 1 else ''}: {', '.join(unknown)}; "
            f"available: {', '.join(sorted(available))}"
        )
    return [available[name] for name in requested]


def _print_result(result: RunResult, *, verbose: bool) -> None:
    marker = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP"}[result.status]
    print(f"{marker:4}  {result.sdk:10}  {result.scenario:32}  {result.duration_ms:>6} ms")
    if result.status == "fail" or (verbose and result.failures):
        for failure in result.failures:
            print(f"      - {failure}")
    if result.status == "fail" and result.stderr.strip():
        for line in result.stderr.strip().splitlines()[-12:]:
            print(f"      | {line}")


def _skip_policy_failures(results: list[RunResult], allowed: set[str]) -> list[str]:
    actual = {result.scenario for result in results if result.status == "skip"}
    failures: list[str] = []
    unexpected = sorted(actual - allowed)
    stale = sorted(allowed - actual)
    if unexpected:
        failures.append("unexpected skips: " + ", ".join(unexpected))
    if stale:
        failures.append("allowed skips did not occur: " + ", ".join(stale))
    return failures


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tr-conformance",
        description="Run black-box fault scenarios through TrustedRouter SDKs",
    )
    parser.add_argument("--list", action="store_true", help="list drivers and scenarios")
    parser.add_argument(
        "--sdk",
        default="all",
        help="comma-separated SDK names, or all (default: all)",
    )
    parser.add_argument(
        "--scenario",
        default="all",
        help="comma-separated scenario names, or all (default: all)",
    )
    parser.add_argument(
        "--sdk-root",
        action="append",
        default=[],
        metavar="SDK=PATH",
        help="override an SDK checkout path; may be repeated",
    )
    parser.add_argument(
        "--strict-capabilities",
        action="store_true",
        help="fail instead of skip when a driver lacks a required capability",
    )
    parser.add_argument(
        "--allowed-skips",
        default=None,
        metavar="NAMES|none",
        help=(
            "enforce an exact comma-separated scenario skip allowlist; "
            "use none to reject every skip"
        ),
    )
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--process-timeout",
        type=float,
        default=300,
        metavar="SECONDS",
        help="per-driver build and execution timeout (default: 300)",
    )
    parser.add_argument("--json-report", type=Path, metavar="PATH")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        manifests = discover_manifests()
        scenarios = discover_scenarios()
        if args.list:
            print("Drivers:")
            for name, manifest in manifests.items():
                capabilities = ", ".join(sorted(manifest.capabilities)) or "none"
                print(f"  {name:10} {manifest.root_name:28} [{capabilities}]")
            print("Scenarios:")
            for name, scenario in scenarios.items():
                requirements = ", ".join(scenario.requires) or "core"
                print(f"  {name:32} [{requirements}] {scenario.description}")
            return 0
        if args.process_timeout <= 0:
            raise ValueError("--process-timeout must be positive")
        selected_manifests = _select(manifests, _csv(args.sdk), "SDK")
        selected_scenarios = _select(scenarios, _csv(args.scenario), "scenario")
        selected_sdk_names = {manifest.sdk for manifest in selected_manifests}
        roots = _roots(
            args.sdk_root,
            available=set(manifests),
            selected=selected_sdk_names,
        )
        allowed_skips: set[str] | None = None
        if args.allowed_skips is not None:
            allowed_skips = set()
            if args.allowed_skips.strip().lower() != "none":
                allowed_skips = set(_csv(args.allowed_skips))
            selected_scenario_names = {scenario.name for scenario in selected_scenarios}
            unknown_allowed = sorted(allowed_skips - selected_scenario_names)
            if unknown_allowed:
                raise ValueError(
                    "--allowed-skips names unselected or unknown scenarios: "
                    + ", ".join(unknown_allowed)
                )
    except (ValueError, argparse.ArgumentTypeError) as exc:
        parser.error(str(exc))

    harness_root = repository_root()
    resolved_sdk_roots = {
        manifest.sdk: roots.get(
            manifest.sdk,
            harness_root.parent / manifest.root_name,
        ).resolve()
        for manifest in selected_manifests
    }
    results = run_matrix(
        selected_manifests,
        selected_scenarios,
        sdk_roots=resolved_sdk_roots,
        strict_capabilities=args.strict_capabilities,
        fail_fast=args.fail_fast,
        process_timeout_seconds=args.process_timeout,
    )
    for result in results:
        _print_result(result, verbose=args.verbose)
    counts = {
        status: sum(result.status == status for result in results)
        for status in ("pass", "fail", "skip")
    }
    print(
        f"\n{len(results)} checks: {counts['pass']} passed, "
        f"{counts['fail']} failed, {counts['skip']} skipped"
    )
    skip_policy_failures: list[str] = []
    if allowed_skips is not None:
        skip_policy_failures = _skip_policy_failures(results, allowed_skips)
        for failure in skip_policy_failures:
            print(f"SKIP POLICY FAILURE: {failure}")
    if args.json_report:
        report = {
            "protocol_version": 1,
            "metadata": collect_report_metadata(
                harness_root=harness_root,
                sdk_roots=resolved_sdk_roots,
            ),
            "summary": counts,
            "skip_policy_failures": skip_policy_failures,
            "results": [result.as_dict() for result in results],
        }
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 1 if counts["fail"] or skip_policy_failures else 0


if __name__ == "__main__":
    sys.exit(main())

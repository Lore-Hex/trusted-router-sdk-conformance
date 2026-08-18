from trusted_router_conformance.runner import discover_manifests


def test_capability_baseline_is_explicit() -> None:
    manifests = discover_manifests()
    actual = {name: manifest.capabilities for name, manifest in manifests.items()}
    assert actual == {
        "go": frozenset(
            {
                "core",
                "reserved_header_stripping",
                "retry_500",
                "telemetry_header",
                "transport_fault",
            }
        ),
        "java": frozenset(
            {
                "core",
                "reserved_header_stripping",
                "retry_500",
                "telemetry_header",
                "transport_fault",
            }
        ),
        "javascript": frozenset({"core", "retry_500", "transport_fault"}),
        "python": frozenset({"core", "retry_500", "telemetry_header", "transport_fault"}),
        "rust": frozenset(
            {
                "core",
                "reserved_header_stripping",
                "retry_500",
                "telemetry_header",
                "transport_fault",
            }
        ),
        "swift": frozenset(
            {
                "core",
                "reserved_header_stripping",
                "telemetry_header",
                "transport_fault",
            }
        ),
    }

from trusted_router_conformance.runner import discover_manifests


def test_capability_baseline_is_explicit() -> None:
    manifests = discover_manifests()
    actual = {name: manifest.capabilities for name, manifest in manifests.items()}
    expected = frozenset(
        {
            "body_timeout",
            "caller_cancellation",
            "core",
            "credential_free_oauth",
            "generated_idempotency",
            "model_preservation",
            "redirect_isolation",
            "reserved_header_stripping",
            "retry_500",
            "retry_body_fault",
            "stream_integrity",
            "telemetry_header",
            "transport_fault",
            "unsafe_retry_guard",
        }
    )
    assert actual == {
        sdk: expected for sdk in ("go", "java", "javascript", "python", "rust", "swift")
    }

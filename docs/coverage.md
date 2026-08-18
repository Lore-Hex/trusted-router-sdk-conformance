# Coverage and known deviations

This file is intentionally candid: a skipped capability is unimplemented
coverage, not a passing test. Run with `--strict-capabilities` for a release
gate that permits none of these gaps.

| SDK | Core retry/verdict | Transport reset | Telemetry header | Reserved header while opted out | Plain 500 retry |
| --- | --- | --- | --- | --- | --- |
| Python | yes | yes | yes | current SDK forwards caller value | yes |
| JavaScript | yes | yes | not implemented in current SDK | not implemented | yes |
| Go | yes | yes | yes | covered by SDK ownership rules | yes |
| Rust | yes | yes | yes | covered by SDK ownership rules | yes |
| Java | yes | yes | yes | covered by SDK ownership rules | yes |
| Swift | yes | yes | yes | covered by SDK ownership rules | current code does not retry 500 |

The Swift README says a 500 retries on the same host, while the current retry
predicate and an existing test permit only one attempt. The `retry-500`
scenario makes that disagreement explicit: Swift omits the `retry_500`
capability, and strict mode fails the omission.

These are source observations, not permanent exemptions. Delete a deviation
and add the corresponding driver capability in the same change that brings an
SDK into conformance.

## Scope boundary for v0.1

The current matrix is the shared **buffered generic-request core**. It covers
successful decoding, 429/500/503 retry decisions, server retry-verdict
overrides, terminal 401 behavior, exact exhaustion, a disconnect before
response headers, stable caller-supplied idempotency keys, telemetry retry
state, and reserved telemetry-header ownership.

It does not yet claim coverage of asynchronous entry points, streaming open
and iteration, a reset or timeout after response headers/body bytes, generated
idempotency keys, regional affinity/failover, or control-plane requests. The
fault server already models delayed and truncated responses, but no v0.1
scenario uses them. In particular, the Swift adapter currently buffers the
physical response before forwarding it; it must move to incremental delegate
callbacks before a mid-body reset scenario can measure Swift faithfully.

Those paths should receive separate capabilities and scenarios rather than be
silently inferred from a buffered-request pass.

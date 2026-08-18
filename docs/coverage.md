# Coverage and known deviations

This file is intentionally candid: a skipped capability is unimplemented
coverage, not a passing test. The v0.2 release gate runs every SDK with no
allowed skips.

| SDK | Core retry + telemetry | SSE integrity | Redirect isolation | Safe replay + generated keys | Body timeout + cancellation | Credential-free OAuth | Typed model preservation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Python | yes | yes | yes | yes | yes | yes | yes |
| JavaScript | yes | yes | yes | yes | yes | yes | yes |
| Go | yes | yes | yes | yes | yes | yes | yes |
| Rust | yes | yes | yes | yes | yes | yes | yes |
| Java | yes | yes | yes | yes | yes | yes | yes |
| Swift | yes | yes | yes | yes | yes | yes | yes |

All six manifests advertise the same complete capability set. The explicit
baseline test fails if a capability disappears or if a new driver is added
without a deliberate coverage decision.

“Redirect isolation” describes the SDK-owned transport, or a supplied
transport that the SDK can safely clone and reconfigure. Some languages expose
an opaque injected transport whose redirect policy or terminal header mutation
cannot be changed after construction. Callers that opt into such a transport
remain responsible for disabling redirects and preventing late credential
injection; each SDK documents that boundary and pins it with native tests. The
shared redirect scenario deliberately uses the SDK-owned/reconfigurable path so
the adapter cannot manufacture a passing result.

## Scope boundary for v0.2

The original buffered generic-request core remains intact. The v0.2 scenarios
add collected SSE integrity, strict redirect isolation, generated
idempotency, unsafe post-send replay prevention, body timeouts, caller
cancellation, credential-free OAuth, typed chat/Responses preservation, and
retry behavior when a diagnostic error body stalls or truncates.

These paths have narrow capabilities. A driver may claim one only when it
invokes the relevant public SDK entry point and its transport adapter preserves
the fault being measured. Native regressions remain required for injected
client/session behavior that a black-box loopback adapter cannot reproduce
without changing SDK semantics.

Regional affinity/failover, first-frame streaming deadlines, byte-level SSE
heartbeat idle timing, and cryptographic attestation validation remain outside
the shared matrix. They should receive dedicated scenarios instead of being
inferred from nearby passing checks.

# Coverage and known deviations

This file is intentionally candid: a skipped capability is unimplemented
coverage, not a passing test. The release gate runs every SDK with no
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

| SDK | Attestation validation | Native regional/domain failover |
| --- | --- | --- |
| Python | yes | yes |
| JavaScript | yes | yes |
| Go | yes | yes |
| Rust | yes | yes |
| Java | yes | yes |
| Swift | yes | yes |

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

## Attestation validation

All six drivers call their public gateway verifier with a fresh RS256 JWT and
ephemeral public JWK. The positive case must verify; rejection cases cover
signature, expiry (expired and absent), issuer, audience, nonce (wrong and
absent), image digest, missing image pin, TLS certificate binding (wrong and
absent), debugging, and secure boot. Only the SDK's typed attestation rejection
counts as a rejected fixture. A build error or unrelated exception cannot pass.

These are offline cryptographic and policy checks, with the fixture bound to
the loopback server's certificate. They do not establish Google hardware trust,
fetch production JWKS, test a live TLS exporter, or prove that prompt transport
is gated on verification. Native session-verification tests remain necessary.

## Regional failover

All six drivers exercise the SDK's native regional-failover option. The common
contract is domain failover from `api.trustedrouter.com` to the independent
`api.allyrouter.com` and `api.uptimerouter.com` endpoints. The same loopback TLS
server captures each logical Host so retrying the original endpoint cannot
masquerade as failover. Requests must retain their body and idempotency key.

Cases cover 503, a 502/504 chain, a transport disconnect, retry-budget
exhaustion, disabling failover, a server retry veto, a retryable 500 that must
not move domains, and respecting an explicitly pinned regional endpoint.
TLS hostname and chain validation stay enabled for every logical endpoint.

This is not regional-affinity selection or a real geographical outage test.
Affinity probes, first-frame streaming deadlines, byte-level SSE heartbeat
idle timing, and live attested transport remain outside the shared matrix.

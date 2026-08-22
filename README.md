# TrustedRouter SDK Conformance

One black-box fault-injection suite for every official TrustedRouter SDK:
Python, JavaScript, Go, Rust, Java, and Swift.

The harness calls each SDK's public API. It does not copy retry policy into six
sets of test doubles. A thin language adapter configures the real client,
routes the logical `https://api.trustedrouter.com` authority to an isolated TLS
loopback server, and emits a normalized result. The shared oracle asserts both
that result and the requests captured on the wire.

```text
scenario.json
     │
     ├── deterministic TLS response / disconnect sequence
     │
real SDK → thin adapter → loopback fault server → wire transcript
     │                                      │
     └──────── normalized result ───────────┴→ shared oracle
```

This catches the failures ordinary unit tests tend to miss: the exact number
of physical attempts, duplicate headers after retries, generated
idempotency-key drift, transport-library recovery, cross-origin replay,
response-body deadlines, cancellation, premature streaming success,
credential scope, typed-model data loss, response-verdict precedence, and
telemetry state carried from one attempt to the next.

## Quick start

Clone this repository next to the SDK repositories:

```text
workspace/
  trusted-router-sdk-conformance/
  trusted-router-py/
  trusted-router-js/
  trusted-router-go/
  trusted-router-rust/
  trusted-router-java/
  trusted-router-swift/
```

Install only the harness tooling, then list or run the matrix:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'

tr-conformance --list
tr-conformance --sdk python,javascript
tr-conformance --sdk all --json-report .conformance/report.json
```

SDK roots default to sibling directories. Any checkout can be selected
explicitly, which is useful for testing a PR worktree:

```bash
tr-conformance \
  --sdk go \
  --sdk-root go=/path/to/trusted-router-go \
  --scenario retry-503,telemetry-retry
```

The drivers compile against those source checkouts, not against an assumed
published version. Language package dependencies may be downloaded by the
native build tool on first use.

## Scenarios and capabilities

Every scenario is a versioned JSON document under `scenarios/`. It specifies:

- the public SDK entry point and operation;
- client retry, timeout, and telemetry configuration;
- an ordered sequence of real socket actions;
- exact outcome and wire-level assertions; and
- capabilities required to run it meaningfully.

Missing capabilities are visible `SKIP`s by default. Use
`--strict-capabilities` to turn every missing contract feature into a failure.
That distinction lets the nightly suite test all current SDKs while strict
release gates prevent known gaps from being mistaken for conformance.

The current capability state and any future gaps exposed by the matrix are
recorded in [`docs/coverage.md`](docs/coverage.md). The harness does not
silently treat an unimplemented behavior as a pass.

## Security and isolation

The server binds only an ephemeral `127.0.0.1` port. For every server run, the
harness creates a fresh in-memory private root and a CA-signed, non-CA server
leaf for `api.trustedrouter.com`, `localhost`, and `127.0.0.1`. Drivers trust
only that run's temporary root; no system trust store or `/etc/hosts` mutation
is needed. The CA signing key is never serialized, the temporary leaf key is
deleted after the server TLS context loads it, and the remaining temporary
certificates are removed at shutdown. No certificate or private-key PEM is
stored in the repository or wheel.

The fake API key and request content are fixed test values. Proxy environment
variables are bypassed so a developer's proxy cannot receive them.

The harness filters common credential environment variables before launching a
driver, but it is **not a security sandbox**. Testing an untrusted SDK PR runs
that checkout's build scripts and code with access to the runner's `HOME`,
filesystem permissions, and network. Use a disposable CI runner or isolated VM
with no valuable credentials or files for code you do not trust.

JSON reports include a UTC generation timestamp, harness and selected-SDK Git
SHAs and dirty state, OS/Python details, and best-effort toolchain versions.
Failures in those metadata probes are recorded as unavailable and never make a
conformance run fail. A missing selected SDK checkout still fails its matrix
entries, as it should.

### Beacon traffic

SDK client-telemetry beacon `POST`s to `/v1/client-events` or `/client-events`
are accepted out of band by the fault server. They appear as summaries in each
result transcript's `beacons` list, but do not consume scenario actions, count
as wire attempts, or affect the conformance verdict.

## Development

```bash
ruff check .
pytest
tr-conformance --sdk all --strict-capabilities
```

See [`docs/protocol.md`](docs/protocol.md) for the adapter contract and
[`CONTRIBUTING.md`](CONTRIBUTING.md) for adding scenarios and SDK drivers.
SDK repositories can make this matrix a required PR check using the
[`sdk-pr.yml` reusable workflow](docs/sdk-pr-integration.md).

## License

Apache-2.0.

# Contributing

## Add a scenario

1. Create one versioned JSON file in `scenarios/`.
2. Prefer assertions about observable wire behavior over driver return text.
3. Give every retrying POST a fixed idempotency key and assert it is identical
   across attempts, unless the scenario deliberately exercises a public
   high-level API's generated key. Generated-key scenarios must assert one
   non-empty value is identical on every attempt.
4. Use closed, content-free telemetry regexes. Never loosen a telemetry rule
   to `.*` merely to accommodate a language.
5. Add or extend an oracle/server unit test for new schema or fault behavior.
6. Run the scenario against every capable driver and in strict mode.

Use `operation.entrypoint` when the invariant depends on a typed or streaming
public helper. Do not emulate that helper in the adapter with the generic
request API; doing so would test the adapter instead of the SDK.

If the scenario exposes a real SDK difference, add a narrowly named capability
and document the missing SDKs in `docs/coverage.md`. A capability is temporary
debt tracking, not a way to encode contradictory expected results.

## Add a driver

A driver manifest lives at `drivers/<sdk>/driver.json`. Keep its adapter thin:
parse the v1 environment, construct the public SDK client, configure native
DNS/TLS routing to loopback, invoke the public generic inference request, and
normalize the result. Retry policy, telemetry assembly, and header ownership
must remain inside the real SDK.

Dynamic wrappers may create build files in a temporary directory so the
driver can depend on any source checkout passed through
`TR_CONFORMANCE_SDK_ROOT`. They must not modify that checkout.

## Verification

Run core tooling and then the affected matrix slices:

```bash
ruff check .
pytest
tr-conformance --sdk <sdk> --verbose
tr-conformance --sdk <sdk> --strict-capabilities
```

Review the JSON report when debugging. It includes the normalized SDK error,
stderr, and full wire transcript for every check.

# Harness protocol v1

The process boundary is deliberately small. The orchestrator owns scenarios,
the server, transcripts, and assertions; drivers own only translation into one
SDK's public configuration and request API.

## Orchestrator-to-driver environment

| Variable | Meaning |
| --- | --- |
| `TR_CONFORMANCE_PROTOCOL_VERSION` | Currently `1` |
| `TR_CONFORMANCE_SCENARIO` | Stable scenario name |
| `TR_CONFORMANCE_SDK_ROOT` | Absolute source-checkout path |
| `TR_CONFORMANCE_LOGICAL_BASE_URL` | Known TrustedRouter HTTPS base seen by the SDK |
| `TR_CONFORMANCE_PHYSICAL_ORIGIN` | TLS loopback origin used for routing |
| `TR_CONFORMANCE_CA_CERT` | Absolute path to this server run's ephemeral CA certificate PEM |
| `TR_CONFORMANCE_METHOD` | Request method |
| `TR_CONFORMANCE_ENTRYPOINT` | Public SDK entry point selected by the scenario |
| `TR_CONFORMANCE_PATH` | Relative inference path |
| `TR_CONFORMANCE_BODY_JSON` | Compact JSON request body |
| `TR_CONFORMANCE_HEADERS_JSON` | Compact JSON caller headers |
| `TR_CONFORMANCE_IDEMPOTENCY_KEY` | Native per-call key, or empty |
| `TR_CONFORMANCE_MAX_RETRIES` | Retries after the initial attempt |
| `TR_CONFORMANCE_TIMEOUT_MS` | SDK request timeout in milliseconds |
| `TR_CONFORMANCE_CANCEL_AFTER_MS` | Caller cancellation delay, or empty when cancellation is not requested |
| `TR_CONFORMANCE_TELEMETRY` | `1` or `0` |
| `TR_CONFORMANCE_DEFAULT_HEADERS_JSON` | Headers installed on the injected native HTTP client, used to test credential isolation |

Drivers must disable regional affinity and cross-host failover for core
scenarios, route the logical hostname to the physical socket without changing
what the SDK uses for telemetry/credential scope, and disable lower transport
retries where the transport exposes such a switch. That leaves exactly one
owner of the logical retry budget: the SDK under test.

Redirect and credential-boundary scenarios must exercise an SDK-owned client,
or an injected client the SDK itself clones and constrains. A driver must not
pre-block redirects or pre-strip headers merely to compensate for an opaque
caller-owned transport; those language-specific injection boundaries belong in
native SDK tests and documentation.

The v1 entry points are:

| Value | Required public behavior |
| --- | --- |
| `generic_json` | Generic buffered request API |
| `chat_completions` | High-level collected chat completion API |
| `chat_stream_collect` | High-level chat collector over an SSE response |
| `responses` | High-level buffered Responses API |
| `oauth_exchange` | Credential-free OAuth code exchange |

An adapter must not reproduce SDK parsing, retry, idempotency, redirect, or
credential policy. It selects the named public entry point and serializes the
public result. When cancellation is requested it must use the SDK's native
cancellation surface (context, task, future, signal, or equivalent).

## Driver-to-orchestrator result

The final non-empty stdout line must be one JSON object:

```json
{
  "protocol_version": 1,
  "sdk": "go",
  "scenario": "retry-503",
  "outcome": "success",
  "value": {"ok": true},
  "error": null
}
```

For errors, `outcome` is `error`, `value` is null, and `error` contains at
least stable `type` and human-readable `message` strings. When the SDK exposes
an HTTP status, drivers also emit integer `status_code`; scenarios can assert
it exactly. Expected SDK errors do not make the driver process fail.
Build/configuration crashes may exit non-zero; the orchestrator treats that as
a harness failure even if a partial JSON result was printed.

## Wire transcript

Header names are lowercased and every value remains an array, even when only
one value was received. This makes duplicated reserved or idempotency headers
observable. Bodies are retained as base64 and, when possible, UTF-8 and JSON.
Monotonic timestamps support later timing assertions without relying on wall
clock time.

The fault server currently supports:

- `response`: complete HTTP/1.1 response;
- `disconnect`: TCP reset after the request is captured, before headers; and
- `truncated_response`: declared body length followed by a prefix and reset;
- `cross_origin_redirect`: redirect to the same isolated TLS listener under
  the distinct `localhost` origin, making any follow-up observable; and
- `body_delay_ms` on response actions: send headers immediately, then delay
  the body to exercise body deadlines and cancellation.

A response may contain both a normal buffered body (`json`, `text`, or
`body_base64`) and `stream_text`. The server selects `stream_text` only when
the captured request JSON contains `"stream": true`; otherwise it sends the
buffered variant. This lets one logical high-level scenario respect SDKs that
natively request buffered JSON and SDKs whose collector natively requests SSE.

Actions marked `allow_client_disconnect` expect the client to time out or
cancel while the server is delaying its body; the resulting broken pipe is
therefore not a harness error.

### Beacon traffic

Client-telemetry `POST` requests whose path is `/v1/client-events` or
`/client-events` are handled out of band, with any query string ignored for
matching. The fault server answers them with `202`, records a compact summary
in the transcript's `beacons` list, and never consumes a scenario action or
counts the request as a wire attempt. Beacon presence, absence, and contents
are reported for observation but do not affect the v1 oracle verdict.

New action kinds require a protocol-version change only when old runners
cannot reject or safely ignore them. Additive expectation fields may remain
within v1 when strict schema validation gives a clear error on old runners.

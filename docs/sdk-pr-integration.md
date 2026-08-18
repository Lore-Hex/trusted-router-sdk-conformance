# Gate SDK pull requests

The harness exposes a reusable workflow, so an SDK repository can gate its PRs
without a cross-repository token. Add this job to that SDK's normal workflow:

```yaml
jobs:
  conformance:
    uses: Lore-Hex/trusted-router-sdk-conformance/.github/workflows/sdk-pr.yml@main
    with:
      sdk: go
      allowed_skips: none
```

Use these inputs for the current repositories:

| Repository | `sdk` | `allowed_skips` |
| --- | --- | --- |
| `trusted-router-py` | `python` | `reserved-header-opt-out` |
| `trusted-router-js` | `javascript` | `telemetry-retry,reserved-header-opt-out` |
| `trusted-router-go` | `go` | `none` |
| `trusted-router-rust` | `rust` | `none` |
| `trusted-router-java` | `java` | `none` |
| `trusted-router-swift` | `swift` | `retry-500` |

The allowlist is exact. A new unexpected skip fails, and an allowed skip that
starts passing also fails until the obsolete exception is removed. Every new
scenario therefore enters every SDK PR gate automatically.

The called job checks out two distinct revisions: the caller's SDK revision
(the pull-request merge commit for a normal `pull_request` workflow) and the
exact harness commit containing the reusable workflow. Pinning the `uses:`
reference to a commit SHA therefore pins both the workflow and the harness code
it executes; `@main` intentionally follows the latest harness revision.

The main harness workflow also accepts `repository_dispatch` events of type
`sdk-conformance`. A dispatcher can set one or more `<sdk>_ref` fields and a
unique `run_id` in `client_payload`; this is useful for central/nightly
orchestration, while the reusable workflow is the simpler PR gate. Distinct
API dispatches without `run_id` and distinct manual dispatches receive unique
concurrency keys and do not cancel one another.

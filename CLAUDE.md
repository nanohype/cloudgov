# CLAUDE.md — cloudgov

## Overview

AWS security and cost governance CLI. A single static Go binary that scans a live
AWS account (plus the cluster side: Kubernetes RBAC and nanohype Platform-tenant
conformance) and reports findings as tables, JSON, or SARIF. Read-only — the one
exception is `iam fix` / `remediate`, which write remediation *files* to disk and
never call a mutating cloud API.

Module: `github.com/nanohype/cloudgov`. Go 1.26.

Peer to the rest of the org: it audits what `landing-zone` provisions,
`eks-gitops` installs, and the `eks-agent-platform` operator reconciles. It does
not enforce — the operator does that. It does not grade build-time standards —
fab's quality-check skill does that.

## Command surface

| Group | Commands |
|-------|----------|
| IAM | `iam scan` (unused/overprivileged permissions vs CloudTrail), `iam fix` (Terraform fix files from a scan report) |
| Cost | `cost diff` (spend delta between two windows) |
| Infrastructure hygiene | `orphans`, `storage audit`, `network audit`, `certs`, `tags` |
| Security posture | `secrets scan`, `lambda audit`, `compliance`, `drift`, `audit` (orchestrates all of the above) |
| Cluster | `k8s rbac`, `platform audit` (Platform-tenant conformance) |
| Operational | `inventory`, `quota`, `baseline`, `compare`, `report` |
| Integration | `mcp` (serves the scanners over stdio as an MCP server) |

`AGENTS.md` is the agent-facing front door — MCP tool table, exit codes, merge-gate
usage. Keep it in sync when the command surface changes.

## Architecture

```
main.go
cmd/                      cobra command tree — one file per command group
internal/
  cloud/                  capability interfaces (IAMProvider, CostProvider, …) + shared types
    aws/                  the AWS provider — one file per domain, narrow SDK interfaces
    k8s/                  the Kubernetes provider (RBAC)
  providers/              provider registry: Factory + Registry + generic Resolve[T]
  <domain>/               scanner logic per domain (iam, cost, orphans, storage, …)
  platform/               Platform-tenant conformance auditor
  fix/                    Terraform + shell remediation generators
  compare/                report normalization for compare/report
  output/                 renderers — one file per domain, shared infra in style.go/jsoncore.go
  integration/            provider→scanner→output end-to-end suite
scripts/                  CI gates, each self-testing; lib/ holds their shared helpers
```

The three seams that matter:

### Capability interfaces, not a monolithic provider
`internal/cloud/*.go` defines one narrow interface per domain (`IAMProvider`,
`StorageProvider`, `QuotaProvider`, …). A provider implements whichever it
supports. Domain scanners in `internal/<domain>/` take a slice of the interface
and know nothing about SDKs, which is what makes them mock-testable without
credentials.

### The registry is the only place SDK wiring lives
Commands never construct a provider. Every `resolveXxxProviders` in `cmd/` is a
one-liner over `providers.Resolve[T](ctx, …)`, which builds `providers.Default()`
and returns every available provider implementing `T`. Adding a provider means
registering a `Factory{Name, Detect, New}` in `internal/providers/registry.go` —
no `cmd/` file changes. `Default()` is a constructor; there is no package-level
mutable registry and no global state.

### Narrow SDK interfaces on the AWS provider
Each file in `internal/cloud/aws/` declares the minimal AWS API surface it needs
(`iamAPI`, `ec2API`, `sqsAPI`, …) and holds it on `Provider`, so tests inject
hand-written mocks. Non-fatal warnings go through `p.warnf`, backed by a
`warnw io.Writer` that `WithQuiet` routes to `io.Discard` — never a bare
`fmt.Fprintf(os.Stderr, …)`. `warnf` also records each message, and `Incomplete()`
returns them: `--quiet` silences the output, not the record.

## Conventions

- Idiomatic Go, small focused packages, no magic.
- Wrap errors with `fmt.Errorf("context: %w", err)`. Never swallow. A per-resource
  probe that fails is the one case where returning no finding is right — but it
  must go through `p.warnf`, which records it so the resource reports as unread
  rather than clean. Dropping the error makes a denied probe indistinguishable
  from a compliant resource.
- Every cloud API call takes a `context.Context`, derived from `cmd.Context()` in
  handlers — never `context.Background()`. The root context is cancelled on the
  first SIGINT/SIGTERM so an interrupt unwinds in-flight requests. CI enforces
  this (`scripts/check-context.sh`).
- No global state. No `init()` side effects beyond cobra registration.
- Business logic lives in `internal/`, not `cmd/`. A `cmd/` file resolves
  providers, calls a scanner, and renders.
- Table output via lipgloss + tabwriter. No bubbletea — there is no interactive TUI.
- A paginator error logs a warning and continues rather than aborting the scan.
  Every `warnf` is recorded as an incomplete observation and surfaces in the run's
  `incomplete` output and exit code 3 — a partial scan must not report as clean.
- Cost figures are on-demand list-price estimates; say so in the finding `Detail`.

### Import aliases

```go
awssdk        "github.com/aws/aws-sdk-go-v2/aws"
cloudaws      "github.com/nanohype/cloudgov/internal/cloud/aws"
cloudk8s      "github.com/nanohype/cloudgov/internal/cloud/k8s"
orphanscanner "github.com/nanohype/cloudgov/internal/orphans"
```

### Tests

All tests run under `go test ./...` with no cloud credentials. Hand-written
interface mocks only — no `gomock`, no `testify/mock`, no generated mocks. Table-driven
(`[]struct{...}` + `t.Run()`). Don't `t.Skip()` around missing credentials; mock instead.

```go
// implement only the methods the test needs
type mockOrphansProvider struct {
    orphans []cloud.OrphanResource
    err     error
}

func (m *mockOrphansProvider) Name() string                 { return "mock" }
func (m *mockOrphansProvider) Detect(_ context.Context) bool { return true }
func (m *mockOrphansProvider) ListOrphans(_ context.Context) ([]cloud.OrphanResource, error) {
    return m.orphans, m.err
}
```

## Making changes

### Add a domain
1. Define the capability interface in `internal/cloud/<domain>.go`.
2. Implement it on the AWS provider in `internal/cloud/aws/<domain>.go` behind a
   narrow SDK interface, with a mock-backed test.
3. Add the scanner in `internal/<domain>/`.
4. Add the renderer in `internal/output/<domain>.go` — that one file owns the
   domain's table renderer, JSON report struct, and writer.
5. Add `cmd/<domain>.go` and register it in `cmd/root.go`.
6. Add a floor for the new package to `.coverage-floors` (CI fails on a tested
   package with no floor).
7. Update the README command reference and the `AGENTS.md` MCP table.

### Add a provider
Register a `Factory{Name, Detect, New}` in `internal/providers/registry.go`.
`Detect` must be cheap (credential resolution, no API calls). The command
resolvers need no edits — they resolve by capability.

## Verification

```bash
task build            # compile
task test             # go test ./...
task test:cover       # coverage profile
task lint             # golangci-lint
```

`.claude/skills/verify` covers build, test and lint. CI
(`.github/workflows/ci.yml`) adds `go vet` and every script in `scripts/` —
`check-gates.sh` fails when one of them is not run by a workflow or not named in
CONTRIBUTING.md, so the set here does not have to be restated to stay true.

`scripts/coverage.sh` enforces `.coverage-floors`, failing on below-floor
coverage, a floored package or file with no coverage data (a stale name), or a
tested package with no floor (ungated new code).

Two kinds of floor. Package floors ratchet: set a few points below current, and
raised when coverage is raised — a ratchet nobody ratchets stops being a floor.
File floors do not ratchet; they are pinned at 100 on the paths a package average
cannot see, because a package sits comfortably above its floor while one branch
inside it goes untested. The rule for which files earn one: a file whose branch
decides whether a security finding is reported at all, or what verdict a reader
is handed. `.coverage-floors` names them with the reason beside each, so the set
is read there rather than restated here. A defensive branch that cannot be
reached carries `//coverage:ignore` with the reason, and the gate reports how
many it honoured so they cannot accumulate.

Releases go out via goreleaser on a `v*` tag.

## Guardrails

- Don't add an external dependency when stdlib or an existing dep works.
- Don't change a capability interface without updating every implementation and
  every call site.
- Don't put cloud SDK wiring in `cmd/` — it goes in a provider factory.
- Don't emit real AWS account IDs in docs, tests, or fixtures.

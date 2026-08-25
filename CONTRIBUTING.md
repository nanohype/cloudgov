# Contributing to cloudgov

## Prerequisites

- Go 1.26+
- [Task](https://taskfile.dev) (`brew install go-task/tap/go-task`)
- Cloud credentials are **not** required for tests — all tests use mocks

## Build & test

```bash
task build                          # compile binary
go test ./...                       # run all tests (no credentials needed)
go vet ./...                        # static analysis
task lint                           # golangci-lint
bash scripts/coverage.sh            # tests + the per-package coverage floors
bash scripts/check-context.sh       # every cloud call threads the signal-aware context
bash scripts/check-release-urls.sh  # documented download URLs match .goreleaser.yaml
bash scripts/check-gates.sh         # every gate above is run by a workflow
bash scripts/check-version-pins.sh  # every pinned version is watched by Renovate
bash scripts/check-doc-paths.sh     # every file named in markdown exists
bash scripts/check-positive-controls.sh  # every gate rejects the violation it exists to catch
```

CI blocks a pull request on every one of these, so a change that skips any of
them here finds out on the PR instead. `.claude/skills/verify` covers build, test
and lint; the gate scripts are not in it, and the coverage floors are the gate a
change is most likely to trip.

---

## Proving a gate can reject

Every gate in `scripts/` proves this on each run: it self-tests against fixtures,
and `scripts/check-positive-controls.sh` introduces the violation it exists to
catch into this working tree and requires a non-zero exit. A gate with no control
fails that run, so the suite cannot shrink to the gates someone remembered.

The three third-party scanners in `.github/workflows/security.yml` are outside
that harness — feeding CI a deliberately vulnerable module to watch a scanner
fire is not a thing to leave in a repository. Being wired into a workflow is not
evidence a scanner rejects, so demonstrate each one by hand rather than assuming:

```sh
# zizmor: a workflow with pull_request_target, write-all, a floating action tag
# and an interpolated PR title
zizmor --offline --persona=regular /path/to/a/deliberately-bad/workflows/

# gosec: a package using crypto/md5 and exec.Command("sh", "-c", ...)
gosec -severity medium -exclude=G304 ./...

# govulncheck: a throwaway module requiring a version with a known advisory
govulncheck ./...
```

Each must exit non-zero on the bad input and zero on this repository. Run it when
you change a scanner's version, its flags, or the shape of what it scans — those
are the changes that turn a gate into a step that always passes.

---

## How to add a new provider

A provider is a struct that implements the cloud interfaces for a specific target.
The existing providers are `internal/cloud/aws` (the primary target) and `internal/cloud/k8s` (Kubernetes RBAC).

### 1. Create the package

```
internal/cloud/<name>/
    <name>.go        # Provider struct, New(), Name(), Detect()
    iam.go           # IAMProvider methods
    orphans.go       # OrphansProvider methods
    storage.go       # StorageProvider methods
    cost.go          # CostProvider methods
```

### 2. Implement the base interface

`internal/cloud/provider.go` defines:

```go
type Provider interface {
    Name() string
    Detect(ctx context.Context) bool
}
```

`Name()` returns a lowercase identifier (e.g. `"aws"`, `"k8s"`).
`Detect()` returns `true` when credentials or environment variables for this provider are available.

```go
// internal/cloud/mycloud/mycloud.go
package mycloud

import "context"

type Provider struct {
    // SDK config, credentials, etc.
}

func New(ctx context.Context) (*Provider, error) {
    // load credentials from env / SDK default chain
    // return error if credentials are not present
}

func (p *Provider) Name() string { return "mycloud" }

func (p *Provider) Detect(ctx context.Context) bool {
    _, err := New(ctx)
    return err == nil
}
```

### 3. Implement the domain interfaces

Each interface is defined in `internal/cloud/`:

| File | Interface | Methods |
|------|-----------|---------|
| `iam.go` | `IAMProvider` | `ListPrincipals`, `GrantedPermissions`, `UsedPermissions`, `MinimalPolicy` |
| `orphans.go` | `OrphansProvider` | `ListOrphans` |
| `storage.go` | `StorageProvider` | `AuditStorage` |
| `cost.go` | `CostProvider` | `GetCostDiff` |
| `inventory.go` | `InventoryProvider` | `ListResources` |
| `quota.go` | `QuotaProvider` | `ListQuotas` |

Each method receives a `context.Context` as its first argument. Wrap all errors with context:

```go
func (p *Provider) ListOrphans(ctx context.Context) ([]cloud.OrphanResource, error) {
    resp, err := p.client.ListDisks(ctx, ...)
    if err != nil {
        return nil, fmt.Errorf("mycloud list disks: %w", err)
    }
    // ...
}
```

### 4. Register a factory in the provider registry

`internal/providers` is the single seam through which commands obtain providers. A
command never constructs one — it asks the registry for every provider whose
credentials are present that implements the capability it needs. Registering your
provider is the only wiring step; no `cmd/` file changes.

Add a `Factory` — `Name()`, a cheap `Detect()`, and a `New()` that builds the SDK
clients — and register it in `Default()` (`internal/providers/registry.go`):

```go
// internal/providers/registry.go
type mycloudFactory struct{}

func (f mycloudFactory) Name() string { return "mycloud" }

func (f mycloudFactory) Detect(ctx context.Context) bool {
    p, err := cloudmycloud.New(ctx)
    return err == nil && p.Detect(ctx)
}

func (f mycloudFactory) New(ctx context.Context) (cloud.Provider, error) {
    return cloudmycloud.New(ctx)
}

func Default(opts ...Option) *Registry {
    var o options
    for _, opt := range opts {
        opt(&o)
    }
    return NewRegistry(
        newAWSFactory(o.profile, o.quiet),
        mycloudFactory{},
    )
}
```

`Detect` must stay cheap — credential resolution only, no API calls beyond it. A factory
that detects but fails to construct is skipped with a warning rather than failing the
whole run, so one misconfigured cloud doesn't sink the others.

That's all. Every `resolveXxxProviders` in `cmd/` is already a one-liner over the
generic `Resolve[T]`, which returns each available provider implementing the capability:

```go
// cmd/orphans.go — unchanged when a provider is added
func resolveOrphansProviders(ctx context.Context) ([]cloud.OrphansProvider, error) {
    return providers.Resolve[cloud.OrphansProvider](ctx, providers.WithQuiet(quiet))
}
```

Your provider is picked up by every domain whose interface it implements, and ignored by
the rest. `Resolve` errors with "no cloud provider detected" only when no available
provider offers the capability.

Registry behavior is covered by `internal/providers/registry_test.go` — add cases there
for the capabilities your factory contributes.

### 5. Write tests

Create a mock in your test file that implements only the interface under test:

```go
type mockMyCloudOrphansProvider struct {
    orphans []cloud.OrphanResource
    err     error
}

func (m *mockMyCloudOrphansProvider) Name() string { return "mycloud" }
func (m *mockMyCloudOrphansProvider) Detect(_ context.Context) bool { return true }
func (m *mockMyCloudOrphansProvider) ListOrphans(_ context.Context) ([]cloud.OrphanResource, error) {
    return m.orphans, m.err
}
```

Do not use `gomock`, `testify/mock`, or any mock-generation library. Hand-written mocks only.

---

## How to add a new command group

A command group is a top-level cobra command (e.g. `cloudgov iam`, `cloudgov cost`) with one or more sub-commands.

### 1. Create the command file

```
cmd/<group>.go
```

Follow the structure used by existing commands:

```go
package cmd

import (
    "github.com/spf13/cobra"
)

var groupCmd = &cobra.Command{
    Use:   "mygroup",
    Short: "One-line description",
}

var groupSubCmd = &cobra.Command{
    Use:   "action",
    Short: "One-line description",
    RunE:  runGroupAction,
}

var (
    groupFlagFoo string
)

func init() {
    groupSubCmd.Flags().StringVar(&groupFlagFoo, "foo", "", "description")
    groupCmd.AddCommand(groupSubCmd)
}

func runGroupAction(cmd *cobra.Command, _ []string) error {
    ctx := cmd.Context()
    // ...
    return nil
}
```

Handlers must derive their context from `cmd.Context()`, never `context.Background()`. The
root command runs under a context cancelled on the first SIGINT/SIGTERM, so threading
`cmd.Context()` into every cloud call lets an interrupt unwind in-flight requests instead of
leaving them to run to completion. CI enforces this (`scripts/check-context.sh`).

### 2. Register with root

In `cmd/root.go`, add to the `init()` function:

```go
func init() {
    // existing AddCommand calls ...
    rootCmd.AddCommand(groupCmd)
}
```

### 3. Implement provider resolution

If your command needs a cloud provider, follow the resolver pattern used by every existing
command: delegate to the registry's generic `Resolve[T]`, which returns every available
provider implementing your capability as a slice, so the scanner code stays uniform.

```go
func resolveMyGroupProviders(ctx context.Context) ([]cloud.MyGroupProvider, error) {
    return providers.Resolve[cloud.MyGroupProvider](ctx, providers.WithQuiet(quiet))
}
```

Pass `providers.WithProfile(profile)` as well if your command exposes `--profile`. Don't
construct a provider directly in `cmd/` — SDK wiring belongs in a registry factory.

### 4. Add core scanner logic

Business logic lives in `internal/`, not in `cmd/`. Create a new package:

```
internal/<group>/
    scanner.go
    scanner_test.go
```

The scanner accepts a slice of providers and aggregates results:

```go
package mygroup

import (
    "context"
    "fmt"
    "github.com/nanohype/cloudgov/internal/cloud"
)

func Scan(ctx context.Context, providers []cloud.MyGroupProvider) ([]MyResult, error) {
    var results []MyResult
    for _, p := range providers {
        r, err := p.DoSomething(ctx)
        if err != nil {
            return nil, fmt.Errorf("%s: %w", p.Name(), err)
        }
        results = append(results, r...)
    }
    return results, nil
}
```

### 5. Add output formatting

Each domain owns one file, `internal/output/<domain>.go`, holding its table renderer, its
JSON report struct, and the writers for both. Shared infrastructure lives alongside it:
lipgloss styles and helpers in `style.go`, the JSON writer in `jsoncore.go`, and SARIF in
`sarif.go`. Adding a domain adds a file — it never edits a shared renderer.

Table output uses lipgloss + tabwriter, matching the existing style.

### 6. Write tests

```go
// internal/mygroup/scanner_test.go
package mygroup

import (
    "context"
    "fmt"
    "testing"
    "github.com/nanohype/cloudgov/internal/cloud"
)

type mockMyGroupProvider struct {
    name    string
    results []MyResult
    err     error
}

func (m *mockMyGroupProvider) Name() string { return m.name }
func (m *mockMyGroupProvider) Detect(_ context.Context) bool { return true }
func (m *mockMyGroupProvider) DoSomething(_ context.Context) ([]MyResult, error) {
    return m.results, m.err
}

func TestScan(t *testing.T) {
    tests := []struct {
        name      string
        providers []cloud.MyGroupProvider
        wantLen   int
        wantErr   bool
    }{
        {
            name: "aggregates results from multiple providers",
            providers: []cloud.MyGroupProvider{
                &mockMyGroupProvider{name: "p1", results: []MyResult{{}}},
                &mockMyGroupProvider{name: "p2", results: []MyResult{{}, {}}},
            },
            wantLen: 3,
        },
        {
            name: "provider error is returned",
            providers: []cloud.MyGroupProvider{
                &mockMyGroupProvider{name: "p1", err: fmt.Errorf("boom")},
            },
            wantErr: true,
        },
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := Scan(context.Background(), tt.providers)
            if (err != nil) != tt.wantErr {
                t.Fatalf("Scan() error = %v, wantErr %v", err, tt.wantErr)
            }
            if len(got) != tt.wantLen {
                t.Errorf("Scan() len = %d, want %d", len(got), tt.wantLen)
            }
        })
    }
}
```

### 7. Honour the incomplete contract

If the command reads a cloud account, it must gate on what the provider could
not read. Two lines, next to the severity gate:

```go
incomplete := cloud.Incomplete(providers)
gate(findings, func(f cloud.MyGroupFinding) cloud.Severity { return f.Severity })
gateIncomplete(incomplete)
```

and the incompletions travel in the JSON report, so the writer takes them too:

```go
return output.WriteMyGroup(w, findings, incomplete)
```

This is not optional politeness. `cloudgov`'s exit 0 is consumed as evidence
supporting approval, so a scan that could not read part of an account has to be
distinguishable from one that found nothing. `cmd/incomplete_contract_test.go`
fails the build if a command resolves a cloud provider and skips this.

### 8. Register the MCP tool

Every scan is reachable over MCP as well as the CLI. Add it in
`registerMCPTools` (`cmd/mcp.go`), reusing the same `resolve*Providers` helper
and scanner as the CLI handler — the MCP surface must not drift into a second
implementation. There is no exit code over MCP, so the `incomplete` array in the
response is the only carrier: compute it there too.

### 9. Update `AGENTS.md` and the README

Add the tool to the MCP table in `AGENTS.md` and the command to the README
reference. `cmd/incomplete_contract_test.go` fails the build if the AGENTS.md
table and the registered tools disagree in either direction. That table is what
an agent reads to decide which tool to call, so a table naming a tool nothing
registers hands the caller an "unknown tool" error, and one omitting a registered
tool hides it.

---

## Test requirements

- All tests must pass with `go test ./...` and **no cloud credentials**.
- Use table-driven tests (`[]struct{...}` + `t.Run()`).
- Use hand-written mock structs that implement only the interface methods needed by the test. No `gomock`, `testify/mock`, or code-generation tools.
- Do not use `t.Skip()` to skip tests that require credentials — mock instead.
- New packages must have at least one test file.
- Coverage is gated by `.coverage-floors`, enforced in CI by `scripts/coverage.sh`.
  A new package needs a floor entry — CI fails a tested package that has none, and fails any
  package that drops below its floor.
- Package floors are a ratchet: raise one when you raise its coverage. Leaving a floor at the
  number it was set at years ago is how a gate quietly starts permitting a large regression.
- Files on the security-critical path carry a per-file `file <path> 100` floor instead, because a
  package floor averages them with everything around them. Adding a branch to one of those files
  means covering both sides of it in the same change.

## Code conventions

- Wrap errors: `fmt.Errorf("context: %w", err)`. Never swallow errors.
- All cloud API calls must accept and respect a `context.Context`.
- No global state. No `init()` side effects beyond cobra command registration.
- Use the import aliases from `CLAUDE.md` consistently.
- Table output uses lipgloss + tabwriter. No interactive TUI (no bubbletea).
- Do not add comments or docstrings to functions you didn't modify.
- Do not add features, flags, or options beyond what is directly required.

## Submitting changes

1. Fork the repository and create a branch from `main`.
2. Make your changes.
3. Run `task build` — it must exit 0.
4. Run `go test ./...` — all tests must pass.
5. Run `go vet ./...` — no warnings.
6. Run `task lint` — golangci-lint reports no issues.
7. Run `bash scripts/coverage.sh` — every floor met. Raise the floor of any
   package whose coverage you raised; a ratchet nobody ratchets is a note, not a
   floor.
8. Run every gate script: `bash scripts/check-context.sh`,
   `bash scripts/check-release-urls.sh`, `bash scripts/check-gates.sh`,
   `bash scripts/check-version-pins.sh`, `bash scripts/check-doc-paths.sh` and
   `bash scripts/check-positive-controls.sh`. CI runs all of them.
9. Open a pull request with a clear description of what changes and why.

# Contributing to cloudgov

## Prerequisites

- Go 1.26+
- [Task](https://taskfile.dev) (`brew install go-task/tap/go-task`)
- Cloud credentials are **not** required for tests — all tests use mocks

## Build & test

```bash
task build        # compile binary
go test ./...     # run all tests (no credentials needed)
go vet ./...      # static analysis
```

Both must pass before marking any backlog item complete.

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

### 4. Wire the provider into the command resolvers

Each command file in `cmd/` has a `resolveXxxProviders()` function that constructs the
provider(s) for that domain. Today these are single-provider AWS-only constructors — they
build the AWS provider, check `Detect()`, and return it:

```go
// cmd/orphans.go
func resolveOrphansProviders(ctx context.Context) ([]cloud.OrphansProvider, error) {
    p, err := cloudaws.New(ctx)
    if err != nil {
        return nil, fmt.Errorf("initialize aws: %w", err)
    }
    if !p.Detect(ctx) {
        return nil, fmt.Errorf("no AWS credentials detected")
    }
    return []cloud.OrphansProvider{p}, nil
}
```

To add another implementation for a domain, construct it alongside the AWS provider and
append it to the returned slice (skip any provider whose credentials aren't detected):

```go
func resolveOrphansProviders(ctx context.Context) ([]cloud.OrphansProvider, error) {
    var providers []cloud.OrphansProvider
    if p, err := cloudaws.New(ctx); err == nil && p.Detect(ctx) {
        providers = append(providers, p)
    }
    if p, err := cloudmycloud.New(ctx); err == nil && p.Detect(ctx) {
        providers = append(providers, p)
    }
    if len(providers) == 0 {
        return nil, fmt.Errorf("no credentials detected")
    }
    return providers, nil
}
```

Do the same in `resolveIAMProviders`, `resolveStorageProviders`, `resolveCostProviders`,
`resolveInventoryProviders`, and `resolveQuotaProviders` for whichever domains your
provider supports.

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
command. The resolver constructs the AWS provider, verifies credentials with `Detect()`, and
returns it as a slice so the scanner code can stay uniform:

```go
func resolveMyGroupProviders(ctx context.Context) ([]cloud.MyGroupProvider, error) {
    p, err := cloudaws.New(ctx)
    if err != nil {
        return nil, fmt.Errorf("initialize aws: %w", err)
    }
    if !p.Detect(ctx) {
        return nil, fmt.Errorf("no AWS credentials detected")
    }
    return []cloud.MyGroupProvider{p}, nil
}
```

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

Table output goes in `internal/output/table.go` (use lipgloss + tabwriter, matching the existing style).
JSON output goes in `internal/output/json.go`.

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

---

## Test requirements

- All tests must pass with `go test ./...` and **no cloud credentials**.
- Use table-driven tests (`[]struct{...}` + `t.Run()`).
- Use hand-written mock structs that implement only the interface methods needed by the test. No `gomock`, `testify/mock`, or code-generation tools.
- Do not use `t.Skip()` to skip tests that require credentials — mock instead.
- New packages must have at least one test file.
- The analyzer package must maintain >80% coverage (checked before v1.0.0 release).

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
6. Open a pull request with a clear description of what changes and why.

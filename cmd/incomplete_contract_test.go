package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The incomplete/exit-3 contract is a promise made in AGENTS.md and CLAUDE.md:
// a scan that could not read part of an account must not let the unread part
// report as clean. Honouring it is one line per command, which is exactly the
// kind of line a new command forgets — and forgetting it is invisible, because
// the command still works and still exits 0.
//
// This test is the gate for that. It reads the command sources and requires
// every handler that resolves a cloud provider to also gate on what that
// provider could not read.
//
// It is a source-level check rather than a behavioural one on purpose: the
// failure it guards against is an omission, and you cannot write a behavioural
// test for a call site nobody wrote.

var (
	// The population is enumerated by IMPORT, not by construction idiom.
	//
	// The first version of this gate matched three registry idioms — Resolve[T],
	// the resolveXxxProviders helpers, and providers.Default. cmd/platform.go and
	// cmd/k8s.go build providers directly with cloudaws.New / cloudk8s.New and
	// matched none of them, so both sat outside the population entirely and the
	// gate reported full coverage without them. platform.go reads an AWS account
	// with WithQuiet set — the exact option the record-versus-copy proof was
	// written for — and nothing read the record.
	//
	// That is the gate's own failure mode: a coverage claim about what the
	// detector RECOGNISES, stated as a claim about what EXISTS. Enumerating the
	// population independently and requiring every member to be gated or
	// explicitly exempt is what scripts/coverage.sh already does — a floored path
	// with no data fails, and a package with coverage but no floor fails. This
	// now works the same way, so the next construction idiom nobody has invented
	// yet is covered by construction rather than by pattern.
	//
	// Importing internal/cloud alone does not count: that package is types
	// (cloud.Severity, cloud.Finding), and compliance.go, gate.go, remediate.go
	// and repo.go use it without reaching an account.
	//
	// THE LIMIT, STATED. This enumerates every command that reaches an account BY
	// THESE THREE IMPORT PATHS — not, as the sentence above is easy to read,
	// every command that reaches an account. Those coincide today: internal/
	// providers is the only non-cmd package importing a provider package
	// (verified with `go list -deps ./cmd`), so there is no transitive route out
	// of the population. Nothing enforces that. Add internal/scanner tomorrow
	// importing internal/cloud/aws, have a command import that and neither
	// provider package directly, and it escapes — the same shape this gate was
	// rewritten to close, one level up. The durable form computes the population
	// from the import graph rather than from direct imports; until then this
	// comment is the honest statement of what the check covers.
	importsProviderPackage = regexp.MustCompile(`internal/cloud/aws"|internal/cloud/k8s"|internal/providers"`)
	// The two halves of honouring the contract. A command either computes the
	// incompletions itself via cloud.Incomplete, or gates on a report field fed
	// by it — `cloudgov audit` takes the second route, since its runner collects
	// per-capability incompletions into report.Incomplete.
	computesIncomplete = regexp.MustCompile(`cloud\.Incomplete\(|\.Incomplete\b`)
	gatesIncomplete    = regexp.MustCompile(`gateIncomplete\(`)
)

// exemptFromIncompleteGate lists command files that resolve a cloud provider but
// legitimately do not call gateIncomplete, each with the reason. Adding a name
// here is a deliberate act that shows up in review; forgetting the call is not.
var exemptFromIncompleteGate = map[string]string{
	// The MCP server has no exit code to set — it is a request/response surface,
	// so the incomplete record travels in the JSON payload instead. Its tools are
	// covered by TestMCPToolsCarryIncomplete below.
	"mcp.go": "no exit code over MCP; incompletions travel in the response payload",

	// root.go imports internal/providers to build providerOptions(). It runs no
	// scan and reads no account.
	"root.go": "wires provider options; runs no scan",

	// The Kubernetes provider has no partial-observation concept to report. Every
	// error path in internal/cloud/k8s/rbac.go returns rather than skipping a
	// resource — the four `continue`s there are filters (system-reserved roles)
	// and post-finding continues, not dropped probes — and the provider does not
	// implement cloud.IncompleteReporter. Gating it would assert a guarantee the
	// layer beneath cannot supply. If cloudk8s ever grows a skip, delete this
	// entry rather than making it true by adding an empty call.
	"k8s.go": "cloudk8s reports errors, not partial observations; implements no IncompleteReporter",
}

func commandSources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd dir: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		out[name] = string(b)
	}
	if len(out) == 0 {
		t.Fatal("no command sources found; this gate would pass vacuously")
	}
	return out
}

// TestEveryCloudCommandGatesOnIncomplete is the contract gate.
func TestEveryCloudCommandGatesOnIncomplete(t *testing.T) {
	srcs := commandSources(t)

	var checked int
	for name, src := range srcs {
		if !importsProviderPackage.MatchString(src) {
			continue
		}
		if reason, ok := exemptFromIncompleteGate[name]; ok {
			t.Logf("%s exempt: %s", name, reason)
			continue
		}
		checked++
		if !computesIncomplete.MatchString(src) {
			t.Errorf("%s resolves a cloud provider but never calls cloud.Incomplete: "+
				"a scan that could not read part of the account will report as clean", name)
		}
		if !gatesIncomplete.MatchString(src) {
			t.Errorf("%s resolves a cloud provider but never calls gateIncomplete: "+
				"--fail-on cannot return exit 3 for an unread account", name)
		}
	}

	// A gate that checked nothing is a gate that cannot fail. The exact number is
	// asserted in TestIncompleteContractCoverageIsExact.
	if checked == 0 {
		t.Fatal("no command files were checked; the detector matched nothing and would pass vacuously")
	}
}

// TestIncompleteContractDetectorCanFail proves the detector above actually
// discriminates, by running it over sources whose answers are known.
//
// Without this, TestEveryCloudCommandGatesOnIncomplete has the same defect it
// exists to catch: it would pass just as happily if the regexes matched nothing.
func TestIncompleteContractDetectorCanFail(t *testing.T) {
	// The population predicate is about imports now, so the fixtures are files,
	// not function bodies. The case that matters is the last one: a handler that
	// constructs a provider directly, matching no registry idiom. The previous
	// detector missed exactly that shape and let cmd/platform.go run ungated.
	registryStyle := `package cmd

import "github.com/nanohype/cloudgov/internal/providers"

func run() error {
	ps, _ := providers.Resolve[cloud.CertProvider](ctx)
	incomplete := cloud.Incomplete(ps)
	gateIncomplete(incomplete)
	return nil
}`
	directConstruction := `package cmd

import cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"

func run() error {
	p, _ := cloudaws.New(ctx)
	_ = p
	return nil
}`
	typesOnly := `package cmd

import "github.com/nanohype/cloudgov/internal/cloud"

func run() error {
	var s cloud.Severity
	_ = s
	return nil
}`
	noCloud := `package cmd

func run() error { return renderFromFile(path) }`

	for _, tc := range []struct {
		name                        string
		src                         string
		wantInPopulation, wantGated bool
	}{
		{"registry idiom, gated", registryStyle, true, true},
		{"direct construction, ungated — the shape that was missed", directConstruction, true, false},
		{"imports cloud types only, not a provider", typesOnly, false, false},
		{"touches no cloud package", noCloud, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := importsProviderPackage.MatchString(tc.src); got != tc.wantInPopulation {
				t.Errorf("population: got %v, want %v", got, tc.wantInPopulation)
			}
			if got := gatesIncomplete.MatchString(tc.src); got != tc.wantGated {
				t.Errorf("gated: got %v, want %v", got, tc.wantGated)
			}
		})
	}
}

// TestIncompleteContractCoverageIsExact pins the count so the contract can be
// stated precisely in the docs rather than approximately. If a command is added
// or removed, this fails and the number in AGENTS.md gets revisited with it.
func TestIncompleteContractCoverageIsExact(t *testing.T) {
	srcs := commandSources(t)

	var gated, exempt []string
	for name, src := range srcs {
		if !importsProviderPackage.MatchString(src) {
			continue
		}
		if _, ok := exemptFromIncompleteGate[name]; ok {
			exempt = append(exempt, name)
			continue
		}
		if gatesIncomplete.MatchString(src) {
			gated = append(gated, name)
		}
	}

	const wantGated = 14
	if len(gated) != wantGated {
		t.Errorf("commands honouring the incomplete contract: got %d %v, want %d.\n"+
			"If you added or removed a cloud command, update this count and the figure in AGENTS.md.",
			len(gated), gated, wantGated)
	}
	if len(exempt) != len(exemptFromIncompleteGate) {
		t.Errorf("exempt commands present: got %d %v, want %d", len(exempt), exempt, len(exemptFromIncompleteGate))
	}
}

// TestMCPToolsCarryIncomplete covers the exemption above. The MCP server has no
// exit code, so the payload is the only carrier — a tool that drops it leaves an
// agent unable to tell a clean account from an unreadable one.
func TestMCPToolsCarryIncomplete(t *testing.T) {
	b, err := os.ReadFile("mcp.go")
	if err != nil {
		t.Fatalf("read mcp.go: %v", err)
	}
	src := string(b)

	// Every tool that resolves a cloud provider must compute incompletions.
	resolves := len(regexp.MustCompile(`resolve\w+Providers\(ctx\)`).FindAllString(src, -1))
	computes := len(computesIncomplete.FindAllString(src, -1))

	if resolves == 0 {
		t.Fatal("no provider resolutions found in mcp.go; this check would pass vacuously")
	}
	if computes < resolves {
		t.Errorf("mcp.go resolves providers %d times but computes incompletions only %d times: "+
			"a tool that drops it reports an unreadable account as clean", resolves, computes)
	}
}

// TestAGENTSMCPTableMatchesRegisteredTools binds the agent-facing documentation
// to the code it describes.
//
// AGENTS.md is the front door for an agent choosing a tool, and it drifted: it
// listed a `repo_audit` tool that was registered nowhere, so an agent following
// the documentation got "unknown tool". A doc that overstates the code is worse
// than no doc, because it is trusted. This fails the build when the table and
// the registrations disagree in either direction.
func TestAGENTSMCPTableMatchesRegisteredTools(t *testing.T) {
	src, err := os.ReadFile("mcp.go")
	if err != nil {
		t.Fatalf("read mcp.go: %v", err)
	}
	agents, err := os.ReadFile(filepath.Join("..", "AGENTS.md"))
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}

	registered := map[string]bool{}
	// Scoped to &mcp.Tool{Name: ...} so the server's own name is not mistaken
	// for a tool.
	for _, m := range regexp.MustCompile(`mcp\.Tool\{Name:\s*"([a-z_0-9]+)"`).FindAllStringSubmatch(string(src), -1) {
		registered[m[1]] = true
	}
	if len(registered) == 0 {
		t.Fatal("no registered MCP tools found; this check would pass vacuously")
	}

	// Table rows look like: | `tool_name` | description | params |
	documented := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\|\\s*`([a-z_0-9]+)`\\s*\\|").FindAllStringSubmatch(string(agents), -1) {
		documented[m[1]] = true
	}
	if len(documented) == 0 {
		t.Fatal("no documented MCP tools parsed from AGENTS.md; this check would pass vacuously")
	}

	for name := range documented {
		if !registered[name] {
			t.Errorf("AGENTS.md documents MCP tool %q but it is registered nowhere: "+
				"an agent following the docs gets 'unknown tool'", name)
		}
	}
	for name := range registered {
		if !documented[name] {
			t.Errorf("MCP tool %q is registered but absent from the AGENTS.md table: "+
				"an agent choosing from the docs will never find it", name)
		}
	}
}

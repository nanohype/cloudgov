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
	// A handler that resolves a provider capable of reporting incompletions —
	// either directly through the registry, or via this package's resolveXxx
	// helpers (which is how the MCP server reaches the same providers).
	resolvesCloudProvider = regexp.MustCompile(`providers\.Resolve\[cloud\.\w+\]|resolve\w+Providers\(ctx\)|providers\.Default\(`)
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
		if !resolvesCloudProvider.MatchString(src) {
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
	compliant := `
func runThing(cmd *cobra.Command, _ []string) error {
	providers, err := providers.Resolve[cloud.CertProvider](ctx)
	incomplete := cloud.Incomplete(providers)
	gateIncomplete(incomplete)
	return output.WriteCerts(w, findings, incomplete)
}`
	missingBoth := `
func runThing(cmd *cobra.Command, _ []string) error {
	providers, err := providers.Resolve[cloud.CertProvider](ctx)
	return output.WriteCerts(w, findings)
}`
	missingGate := `
func runThing(cmd *cobra.Command, _ []string) error {
	providers, err := providers.Resolve[cloud.CertProvider](ctx)
	incomplete := cloud.Incomplete(providers)
	return output.WriteCerts(w, findings, incomplete)
}`
	noProvider := `
func runReport(cmd *cobra.Command, _ []string) error {
	return renderFromFile(path)
}`

	for _, tc := range []struct {
		name                             string
		src                              string
		wantResolves, wantComp, wantGate bool
	}{
		{"compliant", compliant, true, true, true},
		{"missing both halves", missingBoth, true, false, false},
		{"computes but does not gate", missingGate, true, true, false},
		{"no cloud provider at all", noProvider, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolvesCloudProvider.MatchString(tc.src); got != tc.wantResolves {
				t.Errorf("resolves detector: got %v, want %v", got, tc.wantResolves)
			}
			if got := computesIncomplete.MatchString(tc.src); got != tc.wantComp {
				t.Errorf("computes detector: got %v, want %v", got, tc.wantComp)
			}
			if got := gatesIncomplete.MatchString(tc.src); got != tc.wantGate {
				t.Errorf("gates detector: got %v, want %v", got, tc.wantGate)
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
		if !resolvesCloudProvider.MatchString(src) {
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

	const wantGated = 13
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

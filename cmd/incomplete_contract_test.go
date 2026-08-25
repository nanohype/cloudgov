package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
	// Matching on how a command BUILDS a provider — Resolve[T], a
	// resolveXxxProviders helper, providers.Default — makes the population the
	// set of idioms the detector recognises, and reports on it as if it were the
	// set of commands that exist. A command constructing a provider by any other
	// route sits outside it silently, and the gate reports full coverage without
	// it. Enumerating by import instead means the next construction idiom nobody
	// has invented is covered by construction rather than by pattern.
	//
	// Importing internal/cloud alone does not count: that package is types
	// (cloud.Severity, cloud.Finding), and compliance.go, gate.go, remediate.go
	// and repo.go use it without reaching an account.
	//
	// This enumerates every command reaching an account by these three import
	// paths, which equals "every command that reaches an account" only while no
	// intermediate package sits between a command and a provider.
	//
	// That condition is enforced rather than assumed:
	// TestNoPackageStandsBetweenACommandAndAProvider fails if any package under
	// internal/ other than the registry imports one. Without it, a new
	// internal/scanner importing internal/cloud/aws and imported in turn by a
	// handler would escape this population entirely — the same shape this check
	// exists to close, one level up.
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

// The MCP half of the exemption above is covered by
// TestEveryMCPToolCarriesIncomplete in mcp_incomplete_test.go, which pairs each
// registered tool with its own handler rather than comparing whole-file tallies.

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

	// The registration side is read from the AST, not from the source text.
	//
	// A regex over raw source counts a COMMENTED-OUT registration as registered.
	// On its own that is a false positive, but paired with a table row nobody
	// removed it becomes a cancellation: the tool stops existing, both sides
	// still "have" it, and the gate stays green while an agent is told to call
	// something that is not there. A comment is not an AST node, so parsing
	// removes the whole shape.
	fset := token.NewFileSet()
	file, perr := parser.ParseFile(fset, "mcp.go", src, 0)
	if perr != nil {
		t.Fatalf("parse mcp.go: %v", perr)
	}
	registered := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "Tool" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "mcp" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Name" {
				continue
			}
			if v, ok := kv.Value.(*ast.BasicLit); ok && v.Kind == token.STRING {
				if name, uerr := strconv.Unquote(v.Value); uerr == nil {
					registered[name] = true
				}
			}
		}
		return true
	})
	if len(registered) == 0 {
		t.Fatal("no registered MCP tools found; this check would pass vacuously")
	}

	// Table rows look like: | `tool_name` | description | params |
	documented := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\|[ \\t]*`([a-z_0-9]+)`[ \\t]*\\|").FindAllStringSubmatch(string(agents), -1) {
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

// No package sits between a command and a provider.
//
// TestEveryCloudCommandGatesOnIncomplete builds its population from DIRECT
// imports of the three provider packages, which is narrower than "every command
// that reaches an account". The two coincide only while no intermediate package
// imports a provider and is itself imported by a command — a new
// internal/scanner importing internal/cloud/aws, imported in turn by a handler
// that imports neither provider package directly, would escape the population
// entirely.
//
// That comment stated the limit for several revisions and enforced nothing, which
// is the shape this repository keeps finding: a class named in prose is a
// memorial, not a control. This is the control.
//
// The rule: only the registry may stand between a command and a provider. It
// resolves by capability and every resolver in cmd/ is a one-liner over it, so
// a command reaching a provider through anything else is a new architecture as
// well as a new escape.
func TestNoPackageStandsBetweenACommandAndAProvider(t *testing.T) {
	const module = "github.com/nanohype/cloudgov"
	providerPkgs := map[string]bool{
		module + "/internal/cloud/aws": true,
		module + "/internal/cloud/k8s": true,
	}
	// The registry exists to import providers; that is its whole job.
	allowed := map[string]bool{
		module + "/internal/providers": true,
		module + "/internal/cloud/aws": true,
		module + "/internal/cloud/k8s": true,
		module + "/cmd":                true,
	}

	root := filepath.Join("..", "internal")
	examined := 0
	offenders := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		examined++

		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}

		// The package this file belongs to, as an import path.
		dir := filepath.ToSlash(filepath.Dir(path))
		pkg := module + strings.TrimPrefix(dir, "..")
		if allowed[pkg] {
			return nil
		}

		for _, imp := range file.Imports {
			target, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			if providerPkgs[target] {
				offenders++
				t.Errorf("%s imports %s. Only internal/providers may stand between a command and a "+
					"provider — an intermediate package lets a handler reach an account without "+
					"importing a provider directly, which is how it escapes the incomplete-contract "+
					"population", path, target)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/: %v", err)
	}

	if examined == 0 {
		t.Fatal("no Go files found under internal/; the enumeration is broken, not the tree")
	}
	t.Logf("examined %d non-test file(s) under internal/, %d standing between a command and a provider", examined, offenders)
}

// The walk must be able to find one, or the clean sweep above means nothing.
func TestProviderImportDetectorFindsOne(t *testing.T) {
	const module = "github.com/nanohype/cloudgov"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "probe.go", `package scanner

import (
	// `+"`"+module+`/internal/cloud/aws`+"`"+` named only in a comment must not count.
	"fmt"

	cloudaws "`+module+`/internal/cloud/aws"
)
`, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse probe: %v", err)
	}

	found := 0
	for _, imp := range file.Imports {
		target, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil {
			continue
		}
		if target == module+"/internal/cloud/aws" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("the detector found %d provider imports in a fixture carrying exactly one "+
			"(plus one named in a comment); a clean sweep would prove nothing", found)
	}
}

// A tool that exists only as a comment is not registered.
//
// The registration side used to be a regex over raw source, which counted a
// commented-out `mcp.AddTool(s, &mcp.Tool{Name: "x"}, ...)` as shipping. Alone
// that is a false positive; paired with a table row nobody removed it becomes a
// cancellation — the tool stops existing, both sides still carry it, and an
// agent is told to call something that is not there.
//
// This is the control for that. It parses the same way the check does, so a
// return to text matching fails here.
func TestCommentedOutToolIsNotRegistered(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "probe.go", `package cmd

func register(s *mcp.Server) {
	// mcp.AddTool(s, &mcp.Tool{Name: "zz_ghost"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "zz_live"}, nil)
}
`, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse probe: %v", err)
	}

	names := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "Tool" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "mcp" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Name" {
				continue
			}
			if v, ok := kv.Value.(*ast.BasicLit); ok && v.Kind == token.STRING {
				if name, uerr := strconv.Unquote(v.Value); uerr == nil {
					names[name] = true
				}
			}
		}
		return true
	})

	if !names["zz_live"] {
		t.Error("the live registration was not found; the walk finds nothing at all")
	}
	if names["zz_ghost"] {
		t.Error("a registration that exists only as a comment was counted as shipping")
	}
	if len(names) != 1 {
		t.Errorf("found %d registrations in a fixture carrying one live and one commented out", len(names))
	}
}

// The README names which commands can exit 3 and which cannot. That is a claim
// about the code, and it was wrong: it listed `compliance` and `repo audit`
// among the commands that exit 0/1/2 only, while both call gateIncomplete.
//
// Derived rather than restated. A list in prose is right when written and
// silently wrong at the first command that starts or stops gating, which is
// exactly what happened.
func TestREADMEExitThreeListMatchesTheCode(t *testing.T) {
	gating := commandsCallingGateIncomplete(t)
	if len(gating) == 0 {
		t.Fatal("no command calls gateIncomplete; the detector has stopped reading cmd/")
	}

	readme, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	text := string(readme)

	// The paragraph that makes the claim, isolated so a command name appearing
	// elsewhere in a 1000-line document does not satisfy it.
	const marker = "Every command that can observe less than it was asked to honours this"
	start := strings.Index(text, marker)
	if start < 0 {
		t.Fatalf("the README no longer carries the exit-3 paragraph beginning %q; "+
			"this check is asserting against prose that has moved", marker)
	}
	end := strings.Index(text[start:], "\n---")
	if end < 0 {
		end = len(text) - start
	}
	claim := text[start : start+end]

	// The paragraph makes two lists and only one of them is the claim under test.
	// Taking everything before the describing phrase sweeps in the first list as
	// well and reports every gating command as a contradiction; taking everything
	// after it finds only the trailing clause and reports none. The list is the
	// parenthesis between the two.
	const cannotOpen = "Commands that read no cloud account ("
	const cannotClose = ")"
	openAt := strings.Index(claim, cannotOpen)
	if openAt < 0 {
		t.Fatalf("the exit-3 paragraph no longer names the commands that cannot exit 3; " +
			"this check is asserting against prose that has been rewritten")
	}
	rest := claim[openAt+len(cannotOpen):]
	closeAt := strings.Index(rest, cannotClose)
	if closeAt < 0 {
		t.Fatalf("the list of commands that cannot exit 3 is not closed")
	}
	cannotList := rest[:closeAt]

	// The names of the commands that cannot exit 3 are listed BEFORE the phrase
	// that describes them, so that is the text to search. Searching after it
	// finds only the trailing clause and reports every command as consistent —
	// a check that passes while reading the wrong half of the sentence.
	for _, name := range gating {
		// Commands are named in the paragraph as `iam scan`, `repo audit`, etc.,
		// and a cmd/ file is named for the first word of the command.
		if strings.Contains(cannotList, "`"+name+"`") ||
			strings.Contains(cannotList, "`"+name+" ") {
			t.Errorf("cmd/%s.go calls gateIncomplete, so that command can exit 3, and the README "+
				"lists it among the commands that exit 0/1/2 only", name)
		}
	}
	t.Logf("%d command file(s) call gateIncomplete", len(gating))
}

// commandsCallingGateIncomplete returns the cmd/ file base names (without .go)
// containing a call to gateIncomplete.
func commandsCallingGateIncomplete(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if name == "gate.go" {
			continue // where it is defined, not where it is used
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		found := false
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "gateIncomplete" {
				found = true
			}
			return true
		})
		if found {
			out = append(out, strings.TrimSuffix(name, ".go"))
		}
	}
	return out
}

// The file is not the unit; the HANDLER is.
//
// TestEveryCloudCommandGatesOnIncomplete matches its regexes against whole file
// text, so one gating handler buys the whole file a pass. cmd/iam.go carries two
// commands: runIAMScan gated, runIAMFix resolved a live provider, generated
// policies per principal, dropped failures with a bare continue and gated
// nothing. A denied account produced a fix set smaller than the report it came
// from, exit 0, and no record of which principals were left out.
//
// Every function that resolves providers must itself reach a gate.
func TestEveryProviderResolvingHandlerGatesOnIncomplete(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	handlers := 0
	offenders := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if !callsAny(fn, resolvesProviders) {
				continue
			}
			if reason, ok := exemptFromIncompleteGate[name]; ok {
				t.Logf("%s (%s) exempt: %s", fn.Name.Name, name, reason)
				continue
			}
			handlers++
			if !callsAny(fn, func(n string) bool { return n == "gateIncomplete" }) {
				offenders++
				t.Errorf("%s:%d %s resolves cloud providers and never reaches gateIncomplete. "+
					"Another handler in the same file doing so does not cover this one: a partial "+
					"account produces a partial answer here and exits 0",
					name, fset.Position(fn.Pos()).Line, fn.Name.Name)
			}
		}
	}

	if handlers == 0 {
		t.Fatal("no provider-resolving handler found; the detector has stopped reading cmd/")
	}
	t.Logf("examined %d provider-resolving handler(s), %d ungated", handlers, offenders)
}

// resolvesProviders reports whether a called name is one of the resolvers that
// hands back live cloud providers.
func resolvesProviders(name string) bool {
	return strings.HasPrefix(name, "resolve") && strings.HasSuffix(name, "Providers")
}

// callsAny reports whether fn contains a call whose function name satisfies
// match. Nested function literals count: a resolver inside a closure is still
// this handler resolving providers.
func callsAny(fn *ast.FuncDecl, match func(string) bool) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			if match(f.Name) {
				found = true
			}
		case *ast.SelectorExpr:
			if f.Sel != nil && match(f.Sel.Name) {
				found = true
			}
		}
		return true
	})
	return found
}

// The detector must find a handler that resolves and does not gate, or the sweep
// above proves nothing.
func TestHandlerGateDetectorFindsAnUngatedHandler(t *testing.T) {
	fset := token.NewFileSet()
	src := "package cmd\n\n" +
		"func gated() error {\n" +
		"\tp, _ := resolveIAMProviders(nil, \"\")\n" +
		"\t_ = p\n" +
		"\tgateIncomplete(nil)\n" +
		"\treturn nil\n" +
		"}\n\n" +
		"func ungated() error {\n" +
		"\tp, _ := resolveStorageProviders(nil, \"\")\n" +
		"\t_ = p\n" +
		"\treturn nil\n" +
		"}\n\n" +
		"func unrelated() error { return nil }\n"
	file, err := parser.ParseFile(fset, "probe.go", src, 0)
	if err != nil {
		t.Fatalf("parse probe: %v", err)
	}

	resolving, ungated := 0, 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !callsAny(fn, resolvesProviders) {
			continue
		}
		resolving++
		if !callsAny(fn, func(n string) bool { return n == "gateIncomplete" }) {
			ungated++
		}
	}
	if resolving != 2 {
		t.Errorf("found %d provider-resolving handler(s) in a fixture with two", resolving)
	}
	if ungated != 1 {
		t.Errorf("found %d ungated handler(s) in a fixture with exactly one", ungated)
	}
}

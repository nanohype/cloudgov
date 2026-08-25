package cmd

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/audit"
	"github.com/nanohype/cloudgov/internal/output"
)

// The MCP server has no exit code, so the `incomplete` array in a tool's response
// is the only carrier of "this scan could not see everything it was asked to". A
// tool that drops it reports an unreadable account to an agent as a clean one.
//
// This walks the AST rather than counting occurrences. The tally it replaces
// compared two whole-file numbers — how many times a resolver appeared against
// how many times `Incomplete` appeared — which passes as long as the totals
// happen to line up, so three tools could drop the record and it would still be
// green. Its resolver pattern also required a literal `(ctx)`, missing
// `resolveIAMProviders(ctx, in.Profile)` and `buildAuditProviders(ctx)`
// entirely, so the population it counted was smaller than the population that
// exists.
//
// Parsing also settles the comment question by construction: a comment is not an
// AST node, so a handler cannot satisfy this with one.

// mcpIncompleteExempt names the tools that legitimately do not populate the
// array, each with the reason. Adding a name here is a deliberate act visible in
// review; forgetting to compute the array is not.
var mcpIncompleteExempt = map[string]string{
	"k8s_rbac": "Reads a cluster, not a cloud account. The Kubernetes provider returns errors " +
		"rather than partial observations and implements no IncompleteReporter, so populating " +
		"the array here would assert a guarantee the layer beneath cannot supply.",
	"compliance": "Maps saved JSON reports to a benchmark. It reads files, not an account; " +
		"whatever was incomplete about the scans it reads is recorded in those reports.",
	"audit": "Reads a cloud account and does carry the record, but on audit.Report rather than " +
		"in the handler body: the orchestrator collects every domain's incompletions into " +
		"Report.Incomplete and the renderer emits it. TestAuditReportCarriesIncomplete asserts " +
		"that path, so this exemption is a statement about WHERE the record lives, not a waiver.",
}

// handlerComputesIncomplete reports whether a handler body reaches the incomplete
// record at all — directly through cloud.Incomplete, through a scanner that
// returns its own unread list, or through a report struct that carries the field.
func handlerComputesIncomplete(body ast.Node) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.SelectorExpr:
			// cloud.Incomplete(...), report.Incomplete, drift.Incomplete(...)
			if node.Sel != nil && node.Sel.Name == "Incomplete" {
				found = true
				return false
			}
		case *ast.Ident:
			// The local variable every handler names, and the second return of
			// platform.Audit.
			if node.Name == "incomplete" || node.Name == "unread" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func TestEveryMCPToolCarriesIncomplete(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "mcp.go", nil, 0)
	if err != nil {
		t.Fatalf("parse mcp.go: %v", err)
	}

	type registration struct {
		name     string
		computes bool
	}
	var tools []registration

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "AddTool" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "mcp" {
			return true
		}
		if len(call.Args) < 3 {
			t.Errorf("an mcp.AddTool call has %d arguments; this check cannot read it", len(call.Args))
			return true
		}

		name := toolNameFromArg(call.Args[1])
		if name == "" {
			t.Error("an mcp.AddTool call declares no literal tool name; this check cannot pair it with a handler")
			return true
		}
		handler, ok := call.Args[2].(*ast.FuncLit)
		if !ok {
			t.Errorf("the handler for %s is not a function literal; this check cannot read its body", name)
			return true
		}
		tools = append(tools, registration{name: name, computes: handlerComputesIncomplete(handler.Body)})
		return true
	})

	if len(tools) == 0 {
		t.Fatal("no mcp.AddTool registrations found; this check would pass vacuously")
	}

	seen := map[string]bool{}
	for _, tool := range tools {
		if seen[tool.name] {
			t.Errorf("tool %s is registered more than once", tool.name)
		}
		seen[tool.name] = true

		reason, exempt := mcpIncompleteExempt[tool.name]
		switch {
		case exempt && tool.computes:
			t.Errorf("tool %s is exempt from the incomplete contract but computes the array anyway; "+
				"remove the exemption rather than leaving two answers to the same question (exemption reads: %s)",
				tool.name, reason)
		case exempt:
			// Reading no cloud account, by a reason recorded above.
		case !tool.computes:
			t.Errorf("tool %s reads a cloud account and never reaches the incomplete record; "+
				"over MCP there is no exit code, so an agent cannot tell a clean account from an unreadable one",
				tool.name)
		}
	}

	// The exemption list must describe tools that exist. An entry for a tool that
	// was renamed or removed silently exempts nothing and hides that the list has
	// stopped applying.
	for name, reason := range mcpIncompleteExempt {
		if !seen[name] {
			t.Errorf("mcpIncompleteExempt names %q, which is not a registered tool. The exemption "+
				"applies to nothing (reason on file: %s)", name, reason)
		}
	}

	// The population this examined must be the population that exists. A parser
	// that silently stopped recognising a registration idiom would otherwise
	// report a clean subset as a clean whole.
	registered := countRegisteredTools(t, file)
	if len(tools) != registered {
		t.Errorf("examined %d handlers but %d tools are registered; the walk is missing a registration idiom",
			len(tools), registered)
	}
}

// toolNameFromArg pulls the Name field out of a &mcp.Tool{Name: "x", ...} literal.
func toolNameFromArg(arg ast.Expr) string {
	unary, ok := arg.(*ast.UnaryExpr)
	if !ok {
		return ""
	}
	lit, ok := unary.X.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Name" {
			continue
		}
		value, ok := kv.Value.(*ast.BasicLit)
		if !ok || value.Kind != token.STRING {
			return ""
		}
		name, err := strconv.Unquote(value.Value)
		if err != nil {
			return ""
		}
		return name
	}
	return ""
}

// countRegisteredTools counts &mcp.Tool{...} literals independently of how the
// walk above pairs them with handlers, so the two have to agree.
func countRegisteredTools(t *testing.T, file *ast.File) int {
	t.Helper()
	count := 0
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "Tool" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "mcp" {
			count++
		}
		return true
	})
	return count
}

// The detector has to be able to say no. A handler that reaches nothing named
// Incomplete must read as not computing it, or every tool would pass whatever it
// does.
func TestHandlerComputesIncompleteCanReturnFalse(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "probe.go", `package probe

func silent() { findings := scan(); render(findings) }
func records() { incomplete := cloud.Incomplete(providers); render(incomplete) }
func viaReport() { report := run(); render(report.Incomplete) }
// incomplete
func commented() { findings := scan(); render(findings) }
`, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse probe: %v", err)
	}

	got := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		got[fn.Name.Name] = handlerComputesIncomplete(fn.Body)
	}

	for name, want := range map[string]bool{
		"silent":    false,
		"records":   true,
		"viaReport": true,
		// A comment is not an AST node, so it cannot satisfy the detector. This
		// is the fail-open direction a text matcher has here.
		"commented": false,
	} {
		if got[name] != want {
			t.Errorf("handlerComputesIncomplete(%s) = %v, want %v", name, got[name], want)
		}
	}
}

// mcpSeverity must not silently accept a value it cannot interpret: an
// unrecognised severity ranks 0, which is below every real level, so a caller
// asking for HIGH-and-above findings with a typo receives everything and reads it
// as the tool having found that much.
func TestMCPSeverityRejectsUnknownValues(t *testing.T) {
	for _, valid := range []string{"critical", "HIGH", "Medium", "low", "info", ""} {
		if _, err := resolveMCPSeverity(valid); err != nil {
			t.Errorf("resolveMCPSeverity(%q) rejected a valid severity: %v", valid, err)
		}
	}
	for _, invalid := range []string{"HIGHH", "sev:high", "1", "none"} {
		_, err := resolveMCPSeverity(invalid)
		if err == nil {
			t.Errorf("resolveMCPSeverity(%q) accepted a severity it cannot interpret", invalid)
			continue
		}
		if !strings.Contains(err.Error(), "CRITICAL") {
			t.Errorf("the error for %q does not name the accepted values: %v", invalid, err)
		}
	}
}

// The `audit` tool is exempt from the handler-body check above because its
// incomplete record travels on audit.Report rather than through a local. That
// exemption is only honest while the path it names actually works, so this
// asserts it end to end: a run with incompletions must put them in the rendered
// JSON, which over MCP is the whole of what an agent sees.
func TestAuditReportCarriesIncomplete(t *testing.T) {
	report := &audit.Report{
		Incomplete: []string{"us-west-2: ec2:DescribeInstances denied"},
	}

	var buf bytes.Buffer
	if err := output.WriteAudit(&buf, report); err != nil {
		t.Fatalf("WriteAudit: %v", err)
	}

	var decoded struct {
		Incomplete []string `json:"incomplete"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("the audit tool's payload is not valid JSON: %v", err)
	}
	if len(decoded.Incomplete) != 1 || !strings.Contains(decoded.Incomplete[0], "DescribeInstances") {
		t.Fatalf("the audit payload did not carry the incomplete record: %+v", decoded.Incomplete)
	}
}

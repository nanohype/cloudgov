package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// What ships is a governance CLI an adopter points at their own account, org and
// cluster. A value from the publisher's own estate presented as the product's
// shape is a defect, and a DEFAULT is the form of it hardest to see: nothing in
// the call names it, so a run with no argument reaches an organization, an
// account or a cluster the caller does not own and reports findings about it.
//
// A tool schema is worse again. Over MCP the caller is a model, the default is
// invisible to it, and the description is the whole contract — so an estate value
// there is advertised as the product's answer.
//
// The estate names are the ones that would silently work if compiled in. Import
// paths are excluded by construction: this walks string literals in flag calls,
// struct tags and assignments, never import declarations.
var estateNames = []string{"nanohype", "stxkxs"}

// valueLiterals returns the string literals in n that supply a VALUE, as opposed
// to describing one.
//
// The distinction is the whole rule. `cloudgov` audits a CRD whose API group is
// platform.nanohype.dev, and a help string naming it describes the target — it
// reaches nothing on its own. A DEFAULT is the opposite: nothing in the call
// names it, and a run with no argument goes wherever it points. An earlier form
// of this check read every literal and reported four help strings, which is how
// a rule that cries wolf gets its exclusions widened until it matches nothing.
//
// Three value positions, each a way a default arrives:
//
//	StringVar(&x, name, VALUE, usage)  the flag's default
//	x = VALUE                          an assignment, including the `if x == ""`
//	                                   fallback that gives an absent argument one
//	`jsonschema:"... (default VALUE)"` a default announced to a model
func valueLiterals(n ast.Node) []*ast.BasicLit {
	var out []*ast.BasicLit
	add := func(e ast.Expr) {
		if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			out = append(out, lit)
		}
	}
	switch node := n.(type) {
	case *ast.CallExpr:
		sel, ok := node.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil {
			return nil
		}
		// StringVar(target, name, value, usage) and String(name, value, usage).
		switch sel.Sel.Name {
		case "StringVar", "StringVarP":
			if len(node.Args) >= 4 {
				add(node.Args[2])
			}
		case "String", "StringP":
			if len(node.Args) >= 3 {
				add(node.Args[1])
			}
		}
	case *ast.AssignStmt:
		for _, rhs := range node.Rhs {
			add(rhs)
		}
	case *ast.Field:
		if node.Tag != nil {
			tag, err := strconv.Unquote(node.Tag.Value)
			if err == nil && strings.Contains(strings.ToLower(tag), "default") {
				out = append(out, node.Tag)
			}
		}
	}
	return out
}

func TestNoEstateValueIsACommandDefaultOrToolSchema(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	files := 0
	literals := 0
	offenders := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files++
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			// Import paths are string literals too, and the module path contains
			// the org name by necessity. Skipping the whole declaration is what
			// keeps this rule about values rather than about the package name.
			if _, ok := n.(*ast.ImportSpec); ok {
				return false
			}
			for _, lit := range valueLiterals(n) {
				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					continue
				}
				literals++
				lower := strings.ToLower(value)
				for _, estate := range estateNames {
					if !strings.Contains(lower, estate) {
						continue
					}
					// A URL naming the project's own repository is the product's
					// identity, not an estate value standing in for the caller's.
					if strings.Contains(lower, "github.com/"+estate+"/cloudgov") {
						continue
					}
					offenders++
					t.Errorf("%s:%d supplies the estate value %q as a VALUE (%q). A default that names "+
						"the publisher's own organization, account or cluster makes a call with no "+
						"argument reach something the caller does not own — and over MCP the caller "+
						"cannot see that a default was applied",
						name, fset.Position(lit.Pos()).Line, estate, value)
				}
			}
			return true
		})
	}

	if files == 0 {
		t.Fatal("no cmd source files found; this check would pass vacuously")
	}
	if literals == 0 {
		t.Fatal("no string literals examined; the walk has stopped reading the source")
	}
	t.Logf("examined %d string literal(s) across %d file(s) in cmd/, %d estate value(s)", literals, files, offenders)
}

// The production matcher, exercised on the exact shapes this rule exists for.
// A control running its own walk proves nothing about the walk that ships.
func TestEstateValueDetectorFindsEachValuePosition(t *testing.T) {
	const bt = "`"
	probe := "package probe\n\n" +
		"import \"github.com/nanohype/cloudgov/internal/cloud\"\n\n" +
		"type in struct {\n" +
		"\tOrg string " + bt + `json:"org" jsonschema:"organization (default nanohype)"` + bt + "\n" +
		"}\n\n" +
		"func handler(v string) string {\n" +
		"\torg := v\n" +
		"\tif org == \"\" {\n" +
		"\t\torg = \"nanohype\"\n" +
		"\t}\n" +
		"\treturn org\n" +
		"}\n\n" +
		"func register(f flagSet) {\n" +
		"\tf.StringVar(nil, \"org\", \"nanohype\", \"GitHub organization to audit\")\n" +
		"\tf.StringVar(nil, \"expected\", \"expected-repo-settings.yaml\", \"path to the expected settings\")\n" +
		"}\n\n" +
		"var short = \"Audit nanohype Platform tenants against the eks-agent-platform contract\"\n\n" +
		"type flagSet struct{}\n\n" +
		"func (flagSet) StringVar(p *string, name, value, usage string) {}\n\n" +
		"var _ = cloud.SeverityLow\n"

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "probe.go", probe, 0)
	if err != nil {
		t.Fatalf("parse probe: %v", err)
	}

	// Keyed by LINE, not by value. Two of the three value positions carry the
	// same string, and a set keyed by value collapses them into one — the control
	// then reports two hits for three positions and the missing one is invisible.
	reported := map[int]string{}
	importPathSeen := false
	ast.Inspect(file, func(n ast.Node) bool {
		if _, ok := n.(*ast.ImportSpec); ok {
			importPathSeen = true
			return false
		}
		for _, lit := range valueLiterals(n) {
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				continue
			}
			reported[fset.Position(lit.Pos()).Line] = value
		}
		return true
	})

	if !importPathSeen {
		t.Error("the fixture's import path was never visited, so the exclusion that skips it is untested")
	}

	// Three value positions, each a way a default arrives.
	estate := 0
	for _, value := range reported {
		if strings.Contains(strings.ToLower(value), "nanohype") {
			estate++
		}
	}
	if estate != 3 {
		t.Errorf("the matcher found %d estate value(s) in a fixture carrying one in each of the three "+
			"value positions — the fallback assignment, the flag default and the schema tag: %v",
			estate, reported)
	}

	// The other direction, on the same fixture. A help string describing the
	// audited product is not a value, and reporting it is how this rule gets its
	// exclusions widened until it matches nothing.
	for _, value := range reported {
		if strings.Contains(value, "eks-agent-platform contract") {
			t.Errorf("a help string describing the audited product was reported as a value: %q", value)
		}
	}
}

// Run-scoped flags must reach every command, including the two that construct a
// provider directly.
//
// `--regions` and `--quiet` are set once on the root and are meaningless unless
// every provider is built with them. Two commands needed a concrete
// *cloudaws.Provider — the Platform auditor and its MCP handler — and called
// cloudaws.New themselves with at most WithQuiet, so `platform audit --regions`
// accepted the flag, documented it, and scanned every region anyway.
//
// The rule is not "never call cloudaws.New": it is that a call must take the
// shared option set, so a flag added to the root reaches these two the same way
// it reaches the twelve that resolve by capability.
func TestEveryDirectProviderConstructionTakesTheSharedOptions(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	calls := 0
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
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "New" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "cloudaws" {
				return true
			}
			calls++
			if !usesSharedAWSOptions(call) {
				offenders++
				t.Errorf("%s:%d constructs the AWS provider without awsProviderOptions(); "+
					"a run-scoped flag such as --regions is accepted, documented, and silently "+
					"ignored by this command", name, fset.Position(call.Pos()).Line)
			}
			return true
		})
	}

	if calls == 0 {
		t.Fatal("no direct AWS provider construction found in cmd/; the detector has stopped reading the source")
	}
	t.Logf("examined %d direct construction(s), %d without the shared options", calls, offenders)
}

func usesSharedAWSOptions(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		inner, ok := arg.(*ast.CallExpr)
		if !ok {
			continue
		}
		if ident, ok := inner.Fun.(*ast.Ident); ok && ident.Name == "awsProviderOptions" {
			return true
		}
	}
	return false
}

// The detector must find a bare construction, or the sweep above proves nothing.
func TestDirectConstructionDetectorFindsABareCall(t *testing.T) {
	fset := token.NewFileSet()
	src := "package cmd\n\n" +
		"func good() { _, _ = cloudaws.New(ctx, awsProviderOptions()...) }\n" +
		"func bare() { _, _ = cloudaws.New(ctx) }\n" +
		"func alsoBare() { _, _ = cloudaws.New(ctx, cloudaws.WithQuiet(true)) }\n"
	file, err := parser.ParseFile(fset, "probe.go", src, 0)
	if err != nil {
		t.Fatalf("parse probe: %v", err)
	}
	total, bare := 0, 0
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "New" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "cloudaws" {
			return true
		}
		total++
		if !usesSharedAWSOptions(call) {
			bare++
		}
		return true
	})
	if total != 3 {
		t.Fatalf("found %d construction(s) in a fixture with three", total)
	}
	if bare != 2 {
		t.Errorf("found %d bare construction(s) in a fixture with exactly two — one with no options "+
			"and one passing an option directly instead of the shared set", bare)
	}
}

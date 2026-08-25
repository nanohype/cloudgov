package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

func TestResolveSeverity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		fallback cloud.Severity
		want     cloud.Severity
		wantErr  bool
	}{
		{"exact", "CRITICAL", cloud.SeverityLow, cloud.SeverityCritical, false},
		{"lowercase", "high", cloud.SeverityLow, cloud.SeverityHigh, false},
		{"mixed case", "Medium", cloud.SeverityLow, cloud.SeverityMedium, false},
		{"padded", "  info  ", cloud.SeverityLow, cloud.SeverityInfo, false},
		{"empty takes the fallback", "", cloud.SeverityMedium, cloud.SeverityMedium, false},
		{"empty fallback is legal", "", "", "", false},
		{"typo", "HIHG", cloud.SeverityLow, "", true},
		{"a level this tool does not have", "SEV1", cloud.SeverityLow, "", true},
		{"numeric", "2", cloud.SeverityLow, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSeverity(tc.input, tc.fallback)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveSeverity(%q) accepted a level this tool cannot rank", tc.input)
				}
				if !strings.Contains(err.Error(), "CRITICAL") {
					t.Errorf("the error does not name the accepted levels: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveSeverity(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("resolveSeverity(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// Every level the validator accepts must rank above zero, and every level it
// rejects must be the reason the validator exists.
//
// cloud.SeverityRank returns 0 for anything it does not recognise, and 0 is
// below every real level — so an unvalidated value widens a reporting floor to
// everything and narrows a gate threshold to nothing. Two opposite wrong answers
// from one typo, neither announced.
func TestEveryAcceptedSeverityRanksAboveAnUnknownOne(t *testing.T) {
	if len(acceptedSeverities) == 0 {
		t.Fatal("the accepted vocabulary is empty; every severity would be refused")
	}
	for _, s := range acceptedSeverities {
		if cloud.SeverityRank(s) <= 0 {
			t.Errorf("%s is accepted but ranks %d; it would sort below an unrecognised value",
				s, cloud.SeverityRank(s))
		}
	}
	if cloud.SeverityRank("HIHG") != 0 {
		t.Error("an unrecognised severity no longer ranks 0; the hazard this validator guards has changed shape")
	}
}

// severityUsage renders from the vocabulary it validates against, so a flag
// cannot advertise a level the tool refuses.
func TestSeverityUsageNamesEveryAcceptedLevel(t *testing.T) {
	usage := severityUsage("minimum severity to report")
	for _, s := range acceptedSeverities {
		if !strings.Contains(usage, string(s)) {
			t.Errorf("the help text does not name the accepted level %s: %q", s, usage)
		}
	}
}

// No command may cast a severity string without validating it.
//
// This is the class, not the instance. Thirteen sites did
// `cloud.Severity(strings.ToUpper(someFlag))`, and two MCP handlers bypassed the
// validator that was written to close exactly this — the fix pass reported the
// class closed while a third of the surface still did it. Enumerating the AST is
// what makes a new one fail rather than join them.
// severityCastExempt names files whose cast is of a value this program produced,
// not of a string a caller supplied. Each carries the reason, and each is
// asserted to still apply.
var severityCastExempt = map[string]string{
	"audit.go": "casts the keys of report.Summary.BySeverity, which this program " +
		"filled from cloud.Severity values it produced; there is no caller string here.",
}

var exercisedSeverityExemptions map[string]string

func TestNoCommandCastsAnUnvalidatedSeverity(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	// The one legitimate cast: inside resolveSeverity, which is doing the
	// validating. Naming the file rather than the expression keeps the exemption
	// narrow and visible.
	const validator = "severity.go"

	exercisedSeverityExemptions = map[string]string{}

	files := 0
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
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			// cloud.Severity(<expr>)
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "Severity" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "cloud" {
				return true
			}
			// PER FEATURE, NOT PER SPELLING. An earlier form of this check
			// matched only `cloud.Severity(strings.ToUpper(x))` and therefore
			// walked past `cloud.Severity(min)` in two commands — the same class,
			// one spelling shorter. What matters is not how the string was
			// prepared but that it is a string rather than a literal: any
			// non-literal argument is a value whose membership in the vocabulary
			// nothing has checked.
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				return true
			}
			if name == validator {
				return true
			}
			// The internally produced values, named with the reason each is not a
			// caller-supplied string. An entry naming an expression that no longer
			// appears fails below, so a stale exemption cannot sit here quietly.
			if reason, exempt := severityCastExempt[name]; exempt {
				exercisedSeverityExemptions[name] = reason
				return true
			}
			offenders++
			t.Errorf("%s:%d casts a severity string without validating it. An unrecognised "+
				"level ranks 0, which widens a reporting floor to everything and narrows a gate "+
				"threshold to nothing — use resolveSeverity", name, fset.Position(call.Pos()).Line)
			return true
		})
	}

	if files == 0 {
		t.Fatal("no cmd source files found; this check would pass vacuously")
	}
	t.Logf("examined %d file(s) in cmd/, %d unvalidated cast(s)", files, offenders)

	// An exemption that applies to nothing reads exactly like one that is
	// load-bearing, and it is how a list of them grows past what it covers.
	for name := range severityCastExempt {
		if _, used := exercisedSeverityExemptions[name]; !used {
			t.Errorf("%s is exempted from the severity-cast rule and contains no cast to exempt; "+
				"remove the entry rather than leaving a rule that matches nothing", name)
		}
	}
}

// The detector must be able to find one, or the clean sweep above means nothing.
func TestUnvalidatedSeverityDetectorFindsOne(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "probe.go", `package probe

// cloud.Severity(strings.ToUpper(commented)) must not be found.
func bad() { _ = cloud.Severity(strings.ToUpper(flagValue)) }
func good() { _ = cloud.Severity("HIGH") }
`, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse probe: %v", err)
	}

	found := 0
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "Severity" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "cloud" {
			return true
		}
		inner, ok := call.Args[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		innerSel, ok := inner.Fun.(*ast.SelectorExpr)
		if !ok || innerSel.Sel == nil || innerSel.Sel.Name != "ToUpper" {
			return true
		}
		found++
		return true
	})

	if found != 1 {
		t.Fatalf("the detector found %d unvalidated casts in a fixture carrying exactly one "+
			"(plus one in a comment and one legitimate literal); a clean sweep would prove nothing", found)
	}
}

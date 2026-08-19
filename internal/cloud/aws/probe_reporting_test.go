package aws

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// A per-resource probe that fails and skips the resource must say so through
// warnf before it continues.
//
// This is the invariant the whole incomplete contract rests on from below.
// cmd/incomplete_contract_test.go proves every command carries the incomplete
// array; this proves there is something to put in it. A carrier only reports
// what something hands it, and a bare `continue` on a denied probe hands it
// nothing — so the resource reports as read-and-clean rather than as unread.
//
// That failure got worse, not better, when the contract landed. Before it, an
// absent incomplete array meant a consumer had to assume nothing. Now an empty
// array is a documented, tested, agent-consumable assertion that nothing was
// unread. A silent drop turns "I could not look" into "I looked and it was
// fine", which is the exact shape of reporting a denied HeadBucket as DELETED.
//
// ── Why this is a per-site check and not a per-file one ──
//
// The tempting version greps each provider file for `warnf` and passes the file
// if it finds one. That version is worthless here, and the numbers say why:
// iam.go had five silent drops alongside eight warnf calls, orphans.go one
// alongside four. A file-level gate passes both files while six sites keep
// dropping — it proves the mechanism exists in the file, not that this site
// uses it. Presence of the remedy somewhere is not application of the remedy
// here.

// probeSite is one `if <error condition> { ... continue }` block.
type probeSite struct {
	file   string
	line   int
	warns  bool
	source string
}

// findProbeSites returns every error-checking if-statement whose body skips the
// resource with `continue`, noting whether that body reports through warnf.
func findProbeSites(t *testing.T) []probeSite {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	var sites []probeSite

	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		ast.Inspect(f, func(n ast.Node) bool {
			ifStmt, ok := n.(*ast.IfStmt)
			if !ok || ifStmt.Cond == nil || ifStmt.Body == nil {
				return true
			}
			if !mentionsError(ifStmt.Cond) {
				return true
			}
			if !bodySkips(ifStmt.Body) {
				return true
			}
			pos := fset.Position(ifStmt.Pos())
			sites = append(sites, probeSite{
				file:   name,
				line:   pos.Line,
				warns:  bodyReports(ifStmt.Body),
				source: exprString(ifStmt.Cond),
			})
			return true
		})
	}

	if len(sites) == 0 {
		t.Fatal("no probe sites found in the provider package; this gate would pass vacuously")
	}
	return sites
}

// mentionsError reports whether the condition tests an error for FAILURE —
// specifically, contains an `err != nil` comparison.
//
// The looser "mentions an identifier named err" version was wrong in two
// directions, and both showed up on the first run. `if err == nil && pStr == "*"`
// is a success path that continues after recording a finding, not a dropped
// probe. And `if isLambdaPolicyMissing(err)` classifies a benign absence — a
// function with no resource policy — rather than a failure to read one. Flagging
// either would have had me "fix" correct code by warning about things that
// worked.
func mentionsError(cond ast.Expr) bool {
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || bin.Op != token.NEQ {
			return true
		}
		if ident, ok := bin.Y.(*ast.Ident); !ok || ident.Name != "nil" {
			return true
		}
		ast.Inspect(bin.X, func(m ast.Node) bool {
			if id, ok := m.(*ast.Ident); ok && strings.HasSuffix(strings.ToLower(id.Name), "err") {
				found = true
			}
			return true
		})
		return true
	})
	return found
}

// bodySkips reports whether the block abandons the resource — `continue` skips
// this one, `break` abandons every remaining one.
//
// `break` is the worse case and is matched even though no silent one exists
// today: every paginator break in this package already warns. It is here as a
// tripwire, because `if err != nil { break }` is an ordinary way to stop
// paginating on error, and a silent one truncates the result set while the run
// still reports a complete scan. A gate that only knew about `continue` would
// have a hole shaped like the one it was written to close.
//
// `return` is deliberately not matched: bailing out of the function usually
// propagates the error to a caller, which is a louder and different shape.
//
// Nested function literals are not descended into: a branch inside a closure
// belongs to that closure's own loop, not this one.
func bodySkips(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if br, ok := n.(*ast.BranchStmt); ok && (br.Tok == token.CONTINUE || br.Tok == token.BREAK) {
			found = true
		}
		return true
	})
	return found
}

// bodyReports reports whether the block records the skip through warnf.
func bodyReports(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "warnf" {
			found = true
		}
		return true
	})
	return found
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BinaryExpr:
		return exprString(v.X) + " " + v.Op.String() + " " + exprString(v.Y)
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprString(v.Fun) + "(...)"
	default:
		return fmt.Sprintf("%T", e)
	}
}

// TestEveryProbeSkipIsReported is the gate.
func TestEveryProbeSkipIsReported(t *testing.T) {
	var silent []string
	for _, s := range findProbeSites(t) {
		if !s.warns {
			silent = append(silent, fmt.Sprintf("%s:%d (if %s)", s.file, s.line, s.source))
		}
	}
	if len(silent) > 0 {
		t.Errorf("%d probe failure(s) skip a resource without reporting through warnf.\n"+
			"A denied probe that returns no finding is indistinguishable from a compliant\n"+
			"resource, and the run's incomplete array will assert that nothing was unread:\n  %s",
			len(silent), strings.Join(silent, "\n  "))
	}
}

// TestProbeReportingDetectorCanFail proves the AST detector discriminates,
// including the case a file-level gate gets wrong: a silent site in a file that
// contains other warnf calls.
func TestProbeReportingDetectorCanFail(t *testing.T) {
	for _, tc := range []struct {
		name             string
		src              string
		wantErrCond      bool
		wantSkip         bool
		wantWarnInFirst  bool
		commentOnFailure string
	}{
		{
			name:            "reports before continuing",
			src:             `if err != nil { p.warnf("warn: x: %v\n", err); continue }`,
			wantErrCond:     true,
			wantSkip:        true,
			wantWarnInFirst: true,
		},
		{
			name:            "silent continue",
			src:             `if err != nil { continue }`,
			wantErrCond:     true,
			wantSkip:        true,
			wantWarnInFirst: false,
		},
		{
			name:            "compound error condition still counts",
			src:             `if err != nil || desc.Table == nil { continue }`,
			wantErrCond:     true,
			wantSkip:        true,
			wantWarnInFirst: false,
		},
		{
			name:            "non-error skip is not a probe site",
			src:             `if addr.AssociationId != nil { continue }`,
			wantErrCond:     false,
			wantSkip:        true,
			wantWarnInFirst: false,
		},
		{
			name:            "paginator break that reports is a skip, and an acceptable one",
			src:             `if err != nil { p.warnf("warn: page: %v\n", err); break }`,
			wantErrCond:     true,
			wantSkip:        true,
			wantWarnInFirst: true,
		},
		{
			// The tripwire. No such site exists in the package today; if one is
			// added, it truncates the result set silently and the gate says so.
			name:            "silent break abandons every remaining resource",
			src:             `if err != nil { break }`,
			wantErrCond:     true,
			wantSkip:        true,
			wantWarnInFirst: false,
		},
		{
			name:            "return is not matched; it propagates to a caller",
			src:             `if err != nil { return nil, err }`,
			wantErrCond:     true,
			wantSkip:        false,
			wantWarnInFirst: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ifStmt := parseIfStmt(t, tc.src)
			if got := mentionsError(ifStmt.Cond); got != tc.wantErrCond {
				t.Errorf("mentionsError: got %v, want %v", got, tc.wantErrCond)
			}
			if got := bodySkips(ifStmt.Body); got != tc.wantSkip {
				t.Errorf("bodySkips: got %v, want %v", got, tc.wantSkip)
			}
			if got := bodyReports(ifStmt.Body); got != tc.wantWarnInFirst {
				t.Errorf("bodyReports: got %v, want %v", got, tc.wantWarnInFirst)
			}
		})
	}
}

// TestProbeGateIsNotFileLevel is the correction that prompted the AST approach.
//
// A file with one silent site and several reporting ones must still fail. The
// grep-shaped version of this gate passes such a file, because the remedy is
// present somewhere in it — which is how iam.go's five silent drops hid behind
// its eight warnf calls.
func TestProbeGateIsNotFileLevel(t *testing.T) {
	src := `package aws

func (p *Provider) scan() {
	for _, r := range rs {
		a, err := p.probeOne(r)
		if err != nil {
			p.warnf("warn: probe one: %v\n", err)
			continue
		}
		b, err := p.probeTwo(r)
		if err != nil {
			continue
		}
		_, _ = a, b
	}
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var reporting, silent int
	ast.Inspect(f, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Cond == nil || ifStmt.Body == nil {
			return true
		}
		if !mentionsError(ifStmt.Cond) || !bodySkips(ifStmt.Body) {
			return true
		}
		if bodyReports(ifStmt.Body) {
			reporting++
		} else {
			silent++
		}
		return true
	})

	if reporting != 1 || silent != 1 {
		t.Fatalf("detector miscounted the mixed file: %d reporting, %d silent (want 1 and 1)", reporting, silent)
	}
	// The file contains a warnf, so a file-level grep would pass it. The
	// per-site check must not.
	if !strings.Contains(src, "warnf") {
		t.Fatal("fixture no longer contains a warnf; it would not distinguish the two gate designs")
	}
}

func parseIfStmt(t *testing.T, stmt string) *ast.IfStmt {
	t.Helper()
	src := "package aws\nfunc f() { for { " + stmt + " } }"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse %q: %v", stmt, err)
	}
	var found *ast.IfStmt
	ast.Inspect(f, func(n ast.Node) bool {
		if ifStmt, ok := n.(*ast.IfStmt); ok && found == nil {
			found = ifStmt
		}
		return true
	})
	if found == nil {
		t.Fatalf("no if statement parsed from %q", stmt)
	}
	return found
}

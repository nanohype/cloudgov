package output

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `observed` is one call per writer, which is exactly the kind of call a new
// writer forgets — and forgetting it is invisible, because the writer still
// renders and the key is still there. It is there as `null`, which over MCP,
// where there is no exit code, is indistinguishable from a tool that does not
// report its own coverage at all.
//
// TestEveryEnvelopeAlwaysCarriesIncomplete below proves the bytes for the
// writers it names. It cannot prove anything about a writer nobody added to it,
// and a list is what a writer gets left out of. This is the check that has no
// list.
//
// The population is derived from the shape of what is marshalled, not from a
// roster of writers. A function that hands `writeJSON` a struct carrying an
// incomplete record must normalize it; a function that hands it a struct with no
// such record is outside the population because of what it is, not because
// someone remembered to exempt it. `compareReport` is the second kind today, and
// on the day it gains the field this check starts requiring the normalizer with
// no edit here.
//
// Fail-closed on the case it cannot resolve: a writer marshalling a value it
// received rather than a literal it built could carry the record in a type this
// check cannot see from the syntax alone, so it is required to normalize. That
// is the safe direction — the cost of being wrong is one redundant call, and the
// cost of the other default is the defect this exists to catch.
func TestEveryWriterOfAnIncompleteRecordNormalizesIt(t *testing.T) {
	fset := token.NewFileSet()
	files := packageFiles(t, fset)

	// Types declared in this package that carry an incomplete record. Read from
	// the declarations rather than named here, so a new envelope type joins the
	// population by being written.
	carriesRecord := map[string]bool{}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := spec.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range st.Fields.List {
				for _, name := range field.Names {
					if name.Name == "Incomplete" {
						carriesRecord[spec.Name.Name] = true
					}
				}
			}
			return true
		})
	}
	if len(carriesRecord) == 0 {
		t.Fatal("no envelope type in this package declares an Incomplete field; the enumeration collapsed rather than the package changing")
	}

	var checked int
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			marshalled, marshals := writeJSONArgument(fn)
			if !marshals {
				continue
			}
			// A literal of a type declared here with no incomplete record has
			// nothing to normalize. Anything else does, including a value whose
			// type this check cannot read.
			if literal, isLiteral := marshalled.(*ast.CompositeLit); isLiteral {
				if name, named := literalTypeName(literal); named && !carriesRecord[name] {
					continue
				}
			}
			checked++
			if why := normalizesTheRecord(fn, marshalled); why != "" {
				t.Errorf("%s hands writeJSON a value whose incomplete record is not normalized: %s. "+
					"The key is emitted as null, which a caller cannot tell apart from a tool that does not "+
					"report its own coverage. Normalize it, or marshal a type that carries no record.",
					fn.Name.Name, why)
			}
		}
	}

	// A floor well under the real count, not at-least-one: "matched almost
	// nothing" is the failure that reads as success here, because every writer
	// silently outside the population passes.
	const writerFloor = 12
	if checked < writerFloor {
		t.Fatalf("found %d writer(s) of an incomplete record, under the floor of %d — the enumeration collapsed", checked, writerFloor)
	}
}

// writeJSONArgument returns the value fn hands to writeJSON, and whether it
// calls it at all.
func writeJSONArgument(fn *ast.FuncDecl) (ast.Expr, bool) {
	var arg ast.Expr
	var found bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "writeJSON" || len(call.Args) != 2 {
			return true
		}
		arg = call.Args[1]
		found = true
		return false
	})
	return arg, found
}

// normalizesTheRecord relates the observed call to the value that reaches
// writeJSON, and returns why it does not when it does not.
//
// Asking only whether the function calls `observed` somewhere is not the same
// question. `report.Incomplete = observed(report.Incomplete)` and
// `_ = observed(report.Incomplete)` differ by one token, both contain the call,
// and only one of them normalizes anything — so a presence check green-lights
// exactly the mutant that reintroduces `"incomplete": null`.
//
// Two shapes reach writeJSON here and each has its own answer. A composite
// literal must set its Incomplete field FROM an observed call, and setting it to
// anything else — or omitting it, which leaves the zero value that marshals as
// null — is the defect. A value passed by name must have had its Incomplete
// field ASSIGNED from an observed call somewhere in the function.
func normalizesTheRecord(fn *ast.FuncDecl, marshalled ast.Expr) string {
	if literal, isLiteral := marshalled.(*ast.CompositeLit); isLiteral {
		for _, elt := range literal.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				continue
			}
			key, isIdent := kv.Key.(*ast.Ident)
			if !isIdent || key.Name != "Incomplete" {
				continue
			}
			if isObservedCall(kv.Value) {
				return ""
			}
			return "its Incomplete field is set from something other than observed"
		}
		return "the literal it marshals leaves Incomplete unset, so the key marshals as null"
	}

	base := baseIdent(marshalled)
	if base == "" {
		return "this check cannot tell what value it marshals, so it cannot tell whether the record was normalized"
	}

	var assigned bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, isAssign := n.(*ast.AssignStmt)
		if !isAssign {
			return true
		}
		for i, lhs := range assign.Lhs {
			sel, isSel := lhs.(*ast.SelectorExpr)
			if !isSel || sel.Sel.Name != "Incomplete" {
				continue
			}
			if ident, isIdent := sel.X.(*ast.Ident); !isIdent || ident.Name != base {
				continue
			}
			if i < len(assign.Rhs) && isObservedCall(assign.Rhs[i]) {
				assigned = true
			}
		}
		return true
	})
	if !assigned {
		return "nothing assigns " + base + ".Incomplete from observed before it is marshalled"
	}
	return ""
}

// baseIdent returns the identifier a marshalled value refers to, through one
// address-of. Anything else returns empty, which the caller reports rather than
// assumes.
func baseIdent(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			return baseIdent(v.X)
		}
	}
	return ""
}

func isObservedCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "observed"
}

// literalTypeName returns the name of a composite literal's type when it is a
// plain identifier — a type declared in this package. A literal of an imported
// or anonymous type is not named here, and its writer is required to normalize.
func literalTypeName(lit *ast.CompositeLit) (string, bool) {
	ident, ok := lit.Type.(*ast.Ident)
	if !ok {
		return "", false
	}
	return ident.Name, true
}

// packageFiles parses every non-test Go file in this package.
func packageFiles(t *testing.T, fset *token.FileSet) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		t.Fatal("parsed no files; the enumeration collapsed rather than the package being empty")
	}
	return files
}

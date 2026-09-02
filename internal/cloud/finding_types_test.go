package cloud

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A list of "every finding type this auditor can emit" is only worth having if
// something notices when it stops being every one. This package declares three —
// AllOrphanKinds, RepoFindingTypes and AllPlatformFindingTypes — each sitting
// beside its constants and kept by hand, which is the arrangement a new constant
// slips past: the constant compiles, the auditor emits it, and the list that
// downstream code enumerates is quietly one short.
//
// AllPlatformFindingTypes was in that state as much as the other two. It was
// checked against the SARIF rule table, which is a different question: two
// hand-kept lists agreeing with each other says nothing about either agreeing
// with the constants.
//
// This is what notices. It reads the constant blocks and the list literals out
// of the package source and requires them to agree, in both directions — a
// constant missing from its list, and a list naming a constant that no longer
// exists, are the same drift seen from either side.
//
// The population is derived: any package-level slice of a named type whose
// elements are constants of that type is checked, so a fourth enumeration added
// tomorrow is covered without an edit here — which is the property each list's
// own comment claims and none of them could have alone.
func TestEveryFindingTypeListHoldsEveryConstantOfItsType(t *testing.T) {
	fset := token.NewFileSet()
	files := parsePackage(t, fset)

	constantsByType := map[string][]string{}
	listsByType := map[string]map[string][]string{} // element type -> list name -> members

	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			switch gen.Tok {
			case token.CONST:
				for _, spec := range gen.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						typeName, named := constantTypeName(vs, i)
						if !named {
							continue
						}
						constantsByType[typeName] = append(constantsByType[typeName], name.Name)
					}
				}
			case token.VAR:
				for _, spec := range gen.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Values) != 1 {
						continue
					}
					lit, ok := vs.Values[0].(*ast.CompositeLit)
					if !ok {
						continue
					}
					arr, ok := lit.Type.(*ast.ArrayType)
					if !ok {
						continue
					}
					elem, ok := identName(arr.Elt)
					if !ok {
						continue
					}
					var members []string
					for _, e := range lit.Elts {
						if name, ok := identName(e); ok {
							members = append(members, name)
						}
					}
					if listsByType[elem] == nil {
						listsByType[elem] = map[string][]string{}
					}
					listsByType[elem][vs.Names[0].Name] = members
				}
			}
		}
	}

	var checked int
	for elem, lists := range listsByType {
		constants := constantsByType[elem]
		if len(constants) == 0 {
			// A slice of a type this package declares no constants for is not an
			// enumeration of one; nothing to compare it against.
			continue
		}
		for listName, members := range lists {
			checked++
			for _, missing := range difference(constants, members) {
				t.Errorf("%s declares %s and %s does not name it; a type the auditor can emit is "+
					"absent from the list every consumer of that list enumerates", elem, missing, listName)
			}
			for _, stray := range difference(members, constants) {
				t.Errorf("%s names %s, which is not a declared %s constant; the list has drifted from "+
					"the type it enumerates", listName, stray, elem)
			}
		}
	}

	// A floor, not an at-least-one: an enumeration that found nothing reports
	// every list as consistent, which is the reading that looks like a clean tree.
	const listFloor = 2
	if checked < listFloor {
		t.Fatalf("compared %d finding-type list(s), under the floor of %d — the enumeration collapsed rather than the package changing", checked, listFloor)
	}
}

// constantTypeName returns the type of the i-th name in a const spec.
//
// Two spellings declare a typed constant and both have to be read, because
// reading one is how a list of "every constant of this type" quietly stops being
// every one:
//
//	OrphanDisk OrphanKind = "disk"   // the spec carries the type
//	OrphanDisk = OrphanKind("disk")  // the spec does not; the conversion does
//
// The second has a nil ValueSpec.Type, so a check that skipped those declared a
// constant invisible to itself while its comment promised otherwise.
func constantTypeName(vs *ast.ValueSpec, i int) (string, bool) {
	if vs.Type != nil {
		return identName(vs.Type)
	}
	if i >= len(vs.Values) {
		return "", false
	}
	call, isCall := vs.Values[i].(*ast.CallExpr)
	if !isCall {
		return "", false
	}
	return identName(call.Fun)
}

func identName(e ast.Expr) (string, bool) {
	ident, ok := e.(*ast.Ident)
	if !ok {
		return "", false
	}
	return ident.Name, true
}

// difference returns the members of a that are absent from b, sorted so the
// failure reads the same on every run.
func difference(a, b []string) []string {
	inB := make(map[string]bool, len(b))
	for _, s := range b {
		inB[s] = true
	}
	var out []string
	for _, s := range a {
		if !inB[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func parsePackage(t *testing.T, fset *token.FileSet) []*ast.File {
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

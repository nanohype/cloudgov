package integration

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/fix"
	"github.com/nanohype/cloudgov/internal/network"
	orphanscanner "github.com/nanohype/cloudgov/internal/orphans"
	"github.com/nanohype/cloudgov/internal/storage"
)

// The invariant every remediation writer holds:
//
//	Run against a report that names an escape, it creates no filesystem entry
//	outside the directory it was given.
//
// Observed, not analysed. The property is about where a file ends up, and the
// source has infinite ways to put it there: a variable spelled like a contained
// one, a rename whose destination nobody looked at, a helper in another package,
// a function value, a subprocess. A check that reads the source has to enumerate
// those spellings and buys exactly one round per spelling it learns. Walking the
// filesystem afterwards does not care which of them was used — and a writer that
// escapes cannot pass by being renamed, reordered, or moved to another package.
//
// What this cannot do is prove the property for inputs it does not try. It runs
// each writer against a report whose every caller-controlled string carries an
// escape, which is the surface the defect came in through; it says nothing about
// an escape a writer invents from a value the report does not supply. That limit
// is why the population below is still enumerated from the source: a writer with
// no case here is a writer nothing observed.

// escapes are the shapes a report uses to name somewhere else. Each is placed in
// every caller-controlled string field, so a writer that composes a filename
// from any of them has somewhere to go.
var escapes = []string{
	"../ESCAPED",
	"../../ESCAPED",
	"../../../ESCAPED",
	"sub/ESCAPED",
	"x/../ESCAPED",
	"/tmp/ESCAPED-absolute",
	"..",
	"",
	"-rf",
	"a\nb",
}

// remediationWriters is every function this module calls to write remediation
// files, with a driver that hands it a report carrying one escape.
//
// Enumerated here and checked against the source by
// TestEveryRemediationWriterIsObserved, because "which writers exist" is a fact
// about the source and "where their files land" is not.
var remediationWriters = map[string]func(outDir, escape string) ([]string, error){
	"storage.WriteFixScripts": func(outDir, escape string) ([]string, error) {
		return storage.WriteFixScripts([]cloud.BucketFinding{{
			Severity: cloud.SeverityCritical, Type: cloud.BucketPublicAccess,
			Provider: escape, Bucket: escape, Region: escape, Detail: escape,
			Remediation: "aws s3api put-public-access-block --bucket b",
		}}, outDir)
	},
	"network.WriteFixScripts": func(outDir, escape string) ([]string, error) {
		return network.WriteFixScripts([]cloud.NetworkFinding{{
			Severity: cloud.SeverityCritical, Type: cloud.NetworkAdminPortOpen,
			Provider: escape, Resource: escape, Region: escape, Protocol: escape,
			Port: escape, CIDR: escape, Detail: escape,
			Remediation: "aws ec2 revoke-security-group-ingress --group-id sg-1",
		}}, outDir)
	},
	"orphans.WriteFixScripts": func(outDir, escape string) ([]string, error) {
		return orphanscanner.WriteFixScripts([]cloud.OrphanResource{{
			Kind: cloud.OrphanDisk, ID: escape, Name: escape,
			Region: escape, Provider: escape, Detail: escape,
		}}, outDir)
	},
	"fix.WriteRawPolicies": func(outDir, escape string) ([]string, error) {
		return nil, fix.WriteRawPolicies(map[string]cloud.Policy{
			escape: {Raw: []byte(`{"Version":"2012-10-17"}`)},
		}, outDir)
	},
	"fix.GenerateTerraform": func(outDir, escape string) ([]string, error) {
		findings := []cloud.Finding{{
			Severity: cloud.SeverityCritical, Type: cloud.FindingAdminAccess,
			Provider: "aws", Resource: escape, Detail: escape,
			Principal: &cloud.Principal{ID: escape, Name: escape, Type: cloud.PrincipalRole, Provider: "aws"},
		}}
		policies := map[string]cloud.Policy{escape: {Raw: []byte(`{}`)}}
		return nil, fix.GenerateTerraform(findings, policies, fix.Options{
			OutputDir: outDir, Severity: cloud.SeverityLow,
		})
	},
}

func TestNoRemediationWriterPlacesAnEntryOutsideItsOutputDirectory(t *testing.T) {
	for name, write := range remediationWriters {
		for _, escape := range escapes {
			t.Run(name+"/"+escapeLabel(escape), func(t *testing.T) {
				// The sandbox is the current directory for the duration, so a
				// relative escape lands inside it and is visible to the walk
				// below rather than somewhere the test would never look.
				root := t.TempDir()
				t.Chdir(root)
				out := filepath.Join(root, "out")

				// Somewhere to land that is inside the sandbox and outside the
				// output directory, so an escape that needs an existing parent
				// has one. Its emptiness afterwards is part of the assertion.
				if err := os.MkdirAll(filepath.Join(root, "sub"), 0o750); err != nil {
					t.Fatalf("mkdir: %v", err)
				}

				written, err := write(out, escape)
				// A refusal is a correct outcome and so is a successful write of
				// a safely-named file. What is never correct is an entry outside
				// out, and that is what is asserted rather than the error.
				_ = err

				for _, path := range written {
					abs, absErr := filepath.Abs(path)
					if absErr != nil {
						t.Fatalf("resolve %s: %v", path, absErr)
					}
					if filepath.Dir(abs) != out {
						t.Errorf("reported writing %s, which is not directly inside %s", abs, out)
					}
				}

				for _, path := range entriesUnder(t, root) {
					if path == out || strings.HasPrefix(path, out+string(filepath.Separator)) {
						continue
					}
					if path == filepath.Join(root, "sub") {
						continue // the landing site this test created
					}
					t.Errorf("escape %q put %s outside %s", escape, path, out)
				}
			})
		}
	}
}

// A writer with no case above is a writer nothing observed. Which writers exist
// is a fact about the source, so this half is read from it.
func TestEveryRemediationWriterIsObserved(t *testing.T) {
	// Read from the packages that generate remediation files. A package added to
	// this list without a driver fails; a package NOT in this list is outside the
	// gate, which is why the list is short and the reason is stated: these are
	// the packages cmd/ calls to write remediation output.
	packages := []string{
		"../storage", "../network", "../orphans", "../fix",
	}

	found := 0
	for _, dir := range packages {
		for _, fn := range exportedWritersIn(t, dir) {
			found++
			if _, observed := remediationWriters[fn]; !observed {
				t.Errorf("%s writes remediation files and no case in remediationWriters runs it; "+
					"nothing observes where its output lands", fn)
			}
		}
	}
	if found < len(remediationWriters) {
		t.Errorf("found %d writer(s) in the source and %d driver(s) here; a driver naming a writer "+
			"that no longer exists observes nothing", found, len(remediationWriters))
	}
}

func escapeLabel(s string) string {
	switch s {
	case "":
		return "empty"
	case "a\nb":
		return "newline"
	}
	return strings.NewReplacer("/", "_", ".", "dot", "-", "dash", " ", "_").Replace(s)
}

// entriesUnder returns every regular file and symlink under root.
func entriesUnder(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// exportedWritersIn returns the exported functions in a package directory that
// create the directory they write into.
//
// Derived from the shape rather than listed: a remediation writer is handed an
// output directory and makes it, so a body calling os.MkdirAll is the signature
// of one. A writer added to these packages therefore joins the population by
// being written, and the failure a reader gets is "nothing observes where its
// output lands" rather than silence.
func exportedWritersIn(t *testing.T, dir string) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgName := filepath.Base(dir)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		for _, decl := range file.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fn.Body == nil || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			if makesADirectory(fn) {
				out = append(out, pkgName+"."+fn.Name.Name)
			}
		}
	}
	return out
}

func makesADirectory(fn *ast.FuncDecl) bool {
	var found bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "MkdirAll" || sel.Sel.Name == "Mkdir" {
			found = true
		}
		return true
	})
	return found
}

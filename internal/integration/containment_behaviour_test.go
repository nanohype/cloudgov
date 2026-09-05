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
	absoluteEscapeInside,
	absoluteEscapeOutside,
	"..",
	"",
	"-rf",
	"a\nb",
}

// The two absolute shapes, each replaced per run with a path that has a
// detector.
//
// A literal /tmp path was a case that could not fail. Two of the drivers return
// no paths, so for those the only live detector is the walk — and the walk is
// confined to the sandbox, which is exactly where a /tmp landing is not. A write
// there reported pass with the file on disk, which is worse than not testing the
// shape, because the case is counted.
//
// So one absolute target sits inside the sandbox, where the walk reaches it and
// every driver is covered whether or not it reports what it wrote; and one sits
// outside, asserted by naming it and looking. Neither is a placeholder the
// detector cannot see.
const (
	absoluteEscapeInside  = "\x00absolute-inside"
	absoluteEscapeOutside = "\x00absolute-outside"
)

// remediationWriters is every function this module calls to write remediation
// files, with a driver that hands it a report carrying one escape.
//
// Enumerated here and checked against the source by
// TestEveryExportedCallableIsObservedOrExplained, because "which names a caller
// can invoke" is a fact about the source and "where their files land" is not.
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
		}, fix.Options{OutputDir: outDir})
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

				// Two absolute shapes, and each has a detector. One inside the
				// sandbox, which the walk below reaches; one outside it, which
				// only an explicit Lstat can. A single /tmp literal had neither
				// for the two drivers that return no paths.
				outsideSandbox := filepath.Join(t.TempDir(), "ESCAPED-outside-the-sandbox")
				escape := escape
				switch escape {
				case absoluteEscapeInside:
					escape = filepath.Join(root, "ESCAPED-absolute")
				case absoluteEscapeOutside:
					escape = outsideSandbox
				}

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

				// The half the walk cannot reach. Cheap, and it is the only
				// assertion covering a landing outside the sandbox at all.
				if _, statErr := os.Lstat(outsideSandbox); statErr == nil {
					t.Errorf("escape %q created %s, outside the sandbox entirely", escape, outsideSandbox)
				}
			})
		}
	}
}

// notAWriter names the exported callables in the remediation packages that
// create no file, each with the reason.
//
// The population is EVERY name those packages export that a caller can invoke —
// function, method, or variable holding a function — with no predicate deciding
// which of them writes. A predicate is a reading, and a reading is what chose the
// population when the gate matched a body calling os.MkdirAll: five writers
// repeat that call verbatim, so factoring it into a shared helper — the obvious
// next refactor — produced a sixth writer the gate never learned existed, and it
// landed a file above the output directory. Moving a writer onto a receiver, or
// binding it to a package-level variable, are the same move in a different
// spelling.
//
// So a new exported callable is in the population until someone writes down why
// it is not, and the thing that has to be written is a sentence in review rather
// than a call the gate happens to recognise.
var notAWriter = map[string]string{
	"storage.Scan":             "audits buckets and returns findings; writes nothing",
	"network.Scan":             "audits security groups and returns findings; writes nothing",
	"orphans.Scan":             "lists unused resources and returns them; writes nothing",
	"orphans.TotalMonthlyCost": "sums the estimated cost of a slice of orphans",
	"fix.PathUnder":            "composes and refuses a path; the caller writes",
	"fix.NameComponent":        "refuses a value that cannot be one filename element",
	"fix.CommentText":          "renders a value so it cannot leave its comment line",
}

// Every exported callable in the remediation packages either has a driver above
// or a reason here. Which names exist is a fact about the source and is read from
// it; which of them write is not decided by reading anything.
func TestEveryExportedCallableIsObservedOrExplained(t *testing.T) {
	packages := []string{"../storage", "../network", "../orphans", "../fix"}

	seen := map[string]bool{}
	for _, dir := range packages {
		found := exportedCallablesIn(t, dir)

		// Per package, not just in total. Each of these exports at least a
		// scanner and a writer, so a package contributing nothing means the walk
		// stopped reaching it — a suffix test that stopped matching, a directory
		// that moved — and a total floor set below the sum cannot see one package
		// drop out.
		if len(found) == 0 {
			t.Fatalf("%s contributed no exported callable; the walk does not reach it", dir)
		}

		for _, fn := range found {
			seen[fn] = true
			_, driven := remediationWriters[fn]
			_, explained := notAWriter[fn]
			switch {
			case driven && explained:
				t.Errorf("%s has both a driver and a reason it writes nothing; one of them is wrong", fn)
			case !driven && !explained:
				t.Errorf("%s is exported from a remediation package and nothing observes where its "+
					"output lands. Add a driver to remediationWriters, or say in notAWriter why it "+
					"creates no file. A method and a variable holding a function are callable the "+
					"same way a function is, and are in this population for that reason", fn)
			}
		}
	}

	// A name on either list that no longer exists observes nothing and explains
	// nothing, and hides that the list has drifted from the tree.
	for fn := range remediationWriters {
		if !seen[fn] {
			t.Errorf("remediationWriters drives %s, which these packages do not export", fn)
		}
	}
	for fn := range notAWriter {
		if !seen[fn] {
			t.Errorf("notAWriter explains %s, which these packages do not export", fn)
		}
	}

	// And a floor under the sum, for a collapse that empties every package at
	// once: a walk that reached nothing reports every name as accounted for.
	const exportedFloor = 8
	if len(seen) < exportedFloor {
		t.Fatalf("found %d exported callable(s) across %v, under the floor of %d — the walk collapsed",
			len(seen), packages, exportedFloor)
	}
}

func escapeLabel(s string) string {
	switch s {
	case "":
		return "empty"
	case "a\nb":
		return "newline"
	case absoluteEscapeInside:
		return "absolute_inside_the_sandbox"
	case absoluteEscapeOutside:
		return "absolute_outside_the_sandbox"
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

// exportedCallablesIn returns every exported name in a package directory that a
// caller outside the package can invoke.
//
// Every one, with no predicate over what it does: the caller decides by looking
// each up in two lists a person maintains, and a name in neither is a failure. A
// predicate here would be the reading that chose the population before, and the
// escape it missed was a writer whose mkdir moved into a helper.
//
// Three spellings reach a caller, and all three are collected:
//
//	func Write(...)                 a package-level function
//	func (e *Exporter) Write(...)   a method, named Package.Exporter.Write
//	var Write = func(...)           a package-level variable holding a function
//
// The variables are taken whatever their type, because what a var holds is a
// question for the type checker and this reads syntax: `var Write = os.WriteFile`
// binds a function through an expression no AST can classify, and the branch that
// classified is the one a rename walked out of. An exported var that holds no
// function costs one sentence in notAWriter, which is the fail-safe direction.
//
// Types and constants are not collected, and neither can be called: a method
// declared on a type arrives here as its own declaration, and Go has no constant
// of function type — a function value is not a constant expression.
func exportedCallablesIn(t *testing.T, dir string) []string {
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
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				out = append(out, pkgName+"."+receiverPrefix(d)+d.Name.Name)
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					value, isValue := spec.(*ast.ValueSpec)
					if !isValue {
						continue
					}
					for _, ident := range value.Names {
						if !ident.IsExported() {
							continue
						}
						out = append(out, pkgName+"."+ident.Name)
					}
				}
			}
		}
	}
	return out
}

// receiverPrefix renders a method's receiver type as a name segment, so a method
// is distinguishable from a function of the same name and reads the way it is
// called. A function returns the empty string.
func receiverPrefix(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	expr := fn.Recv.List[0].Type
	if star, isStar := expr.(*ast.StarExpr); isStar {
		expr = star.X
	}
	// A generic receiver is written Type[T]; the type is the thing being indexed.
	if index, isIndex := expr.(*ast.IndexExpr); isIndex {
		expr = index.X
	}
	if list, isList := expr.(*ast.IndexListExpr); isList {
		expr = list.X
	}
	if ident, isIdent := expr.(*ast.Ident); isIdent {
		return ident.Name + "."
	}
	return "?."
}

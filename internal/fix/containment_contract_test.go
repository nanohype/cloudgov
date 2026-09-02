package fix

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Containment is one line per generator, which is exactly the kind of line a new
// generator forgets — and forgetting it is invisible, because the generator
// still works and still writes the file it was asked for. Every value that
// reaches a filename here comes out of a report the operator received rather
// than one cloudgov wrote, so the line that is missing is the one deciding
// where an executable lands.
//
// This is the gate for that. It reads the sources and requires every file that
// creates a file on disk to compose its path through PathUnder.
//
// A source-level check rather than a behavioural one, for the same reason the
// incomplete contract is checked that way: the failure it guards against is an
// omission, and there is no behavioural test for a call site nobody wrote.

// writeCalls are the standard-library calls that create or truncate a file.
//
// The population is enumerated by CALL, not by package or by filename. Matching
// on which packages are known to generate files makes the population the set of
// packages someone remembered, and reports on it as though it were the set that
// writes. A generator in a package this list has never heard of sits outside it
// silently, and the gate reports full coverage without it.
var writeCalls = map[string]bool{
	"WriteFile": true,
	"Create":    true,
	"OpenFile":  true,
}

// containmentExempt names directories whose files create files and legitimately
// do not compose the path, each with the reason. Adding a name here is a
// deliberate act that shows up in review; forgetting a PathUnder call is not.
//
// An exemption is a claim about what a directory does, so the claim is checked
// rather than taken: TestExemptDirectoriesDoNotComposePaths fails if a file in
// one of these starts building a path, and the walk below fails if an entry
// names a directory that creates no files at all.
var containmentExempt = map[string]string{
	"cmd": "Every write here is os.Create on an --output-file flag: a path the " +
		"operator typed, who already holds the authority to name it. Nothing in cmd " +
		"composes a filename, and CLAUDE.md puts the logic that would in internal/, " +
		"so a generator arriving here is already a convention violation before it is " +
		"a containment one.",

	"internal/report": "Writes the HTML report to the --out path the operator " +
		"typed. The input report supplies the report's contents, never its location.",
}

// Floors well under the real counts, not at-least-one. "Matched almost nothing"
// is the failure that reads as success: an at-least-one floor is satisfied by a
// single stray file and reports a clean tree.
//
// Two floors, and they are not the same claim. The first catches a walk that
// collapsed. The second catches one that still sees cmd — eighteen of the write
// sites — while seeing none of the generators, which is the half this gate is
// about.
const (
	writeSiteFloor         = 15
	unexemptWriteSiteFloor = 4
)

func TestEveryFileCreatingWriterComposesThroughPathUnder(t *testing.T) {
	root := repoRoot(t)
	files := goSources(t, root)

	var writeSites, unexempt int
	for _, f := range files {
		writes := callNames(t, f.path, writeCalls, "os")
		if len(writes) == 0 {
			continue
		}
		writeSites += len(writes)
		if exemptDir(f.rel) != "" {
			continue
		}
		unexempt += len(writes)
		if len(callNames(t, f.path, map[string]bool{"PathUnder": true}, "")) == 0 {
			t.Errorf("%s calls %s and never composes its path through PathUnder; "+
				"a filename built from a value cloudgov read can name a file outside the "+
				"directory the caller chose. Compose it with fix.PathUnder, or add the "+
				"directory to containmentExempt with the reason it does not need to.",
				f.rel, strings.Join(writes, ", "))
		}
	}

	if writeSites < writeSiteFloor {
		t.Fatalf("found %d file-creating call(s) across the module, under the floor of %d — "+
			"the enumeration collapsed rather than the tree being clean", writeSites, writeSiteFloor)
	}
	if unexempt < unexemptWriteSiteFloor {
		t.Fatalf("found %d file-creating call(s) outside %v, under the floor of %d — "+
			"the enumeration reached cmd and missed the generators, which is the half this gate is about",
			unexempt, exemptDirs(), unexemptWriteSiteFloor)
	}
}

// An exemption says the directory is handed its paths rather than building
// them. That is a property of the code, so it is checked here instead of being
// carried by the sentence that claims it.
func TestExemptDirectoriesDoNotComposePaths(t *testing.T) {
	root := repoRoot(t)
	files := goSources(t, root)

	covered := make(map[string]bool, len(containmentExempt))
	for _, f := range files {
		dir := exemptDir(f.rel)
		if dir == "" {
			continue
		}
		if len(callNames(t, f.path, writeCalls, "os")) > 0 {
			covered[dir] = true
		}
		if joins := callNames(t, f.path, map[string]bool{"Join": true}, "filepath"); len(joins) > 0 {
			t.Errorf("%s is under the exempt directory %q, whose exemption reads %q — "+
				"but it composes a path with filepath.Join. The exemption no longer describes it.",
				f.rel, dir, containmentExempt[dir])
		}
	}

	// An entry naming a directory that creates no files exempts nothing, and
	// hides that the list has drifted from the tree.
	for dir := range containmentExempt {
		if !covered[dir] {
			t.Errorf("containmentExempt names %q, which contains no file-creating call. "+
				"An exemption for a directory that writes nothing exempts nothing; remove it.", dir)
		}
	}
}

type goSource struct {
	path string
	rel  string
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

// goSources returns every non-test Go file tracked under the module root.
//
// A walk that reaches nothing is a failure rather than a clean tree; the floors
// in the caller are what say so.
func goSources(t *testing.T, root string) []goSource {
	t.Helper()
	var out []goSource
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "dist", "testdata":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		out = append(out, goSource{path: path, rel: filepath.ToSlash(rel)})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// callNames returns the names of the calls in path that match want. When pkg is
// non-empty only qualified calls on that package match (os.WriteFile); when it
// is empty both a bare call and a qualified one match, so the definition counts
// whether it is used from inside this package or imported into another.
//
// Matched on the syntax tree rather than on the file's text: a name in a comment
// or in a string is not a call, and a gate that cannot tell them apart passes on
// prose.
func callNames(t *testing.T, path string, want map[string]bool, pkg string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			ident, isIdent := fn.X.(*ast.Ident)
			if !isIdent || !want[fn.Sel.Name] {
				return true
			}
			if pkg != "" && ident.Name != pkg {
				return true
			}
			found = append(found, ident.Name+"."+fn.Sel.Name)
		case *ast.Ident:
			if pkg == "" && want[fn.Name] {
				found = append(found, fn.Name)
			}
		}
		return true
	})
	return found
}

func exemptDir(rel string) string {
	for dir := range containmentExempt {
		if rel == dir || strings.HasPrefix(rel, dir+"/") {
			return dir
		}
	}
	return ""
}

func exemptDirs() []string {
	dirs := make([]string, 0, len(containmentExempt))
	for dir := range containmentExempt {
		dirs = append(dirs, dir)
	}
	return dirs
}

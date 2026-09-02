package fix

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Containment is one line per write, which is exactly the kind of line a new
// write forgets — and forgetting it is invisible, because the write still
// happens and still produces the file it was asked for. Every value that reaches
// a filename here comes out of a report the operator received rather than one
// cloudgov wrote, so the line that is missing is the one deciding where an
// executable lands.
//
// This is the gate for that. It reads the sources and requires the path handed
// to every file-creating call to have come from PathUnder.
//
// Two things it does NOT do, stated because the alternative is prose that
// overstates a source-level check:
//
//   - The unit is the WRITE, not the file. A file with one contained write and
//     one uncontained write fails. An earlier version asked only whether the file
//     contained a PathUnder call anywhere, so a second write added to an existing
//     generator inherited the first one's containment and escaped.
//
//   - The population of writers is FAIL-CLOSED, not a list. Any call on the
//     standard library's os package is a write unless it is named in
//     osTakesNoPathOrOnlyReads below — so a routine nobody here has heard of
//     demands containment rather than being invisible. The earlier version listed
//     three names and missed os.CreateTemp and os.Rename, which is how this
//     repository's own baseline store already writes.

// osTakesNoPathOrOnlyReads names the os routines that neither create nor place a
// filesystem entry: those taking no path at all, and those that only read one.
//
// The inverse of the set the gate cares about, on purpose. A list of writers is
// a list someone wrote, and the entry it is missing is the one that escapes; a
// list of non-writers makes the DEFAULT "this needs containment", so an os
// routine added to Go tomorrow, or one this repository has not used yet, is
// covered by construction. The cost of being wrong is one redundant PathUnder
// call or one entry added here with a reason; the cost of the other default is
// the defect this exists to catch.
//
// Deliberately absent, though they neither create nor place: Remove, RemoveAll,
// Chmod, Chown, Truncate, Rename. Each acts destructively on a path, and a path
// this tool derived from a report is exactly as untrusted going into those as
// into a write.
var osTakesNoPathOrOnlyReads = map[string]bool{
	// No path.
	"Environ": true, "Executable": true, "Exit": true, "ExpandEnv": true,
	"FindProcess": true, "Getegid": true, "Getenv": true, "Geteuid": true,
	"Getgid": true, "Getgroups": true, "Getpagesize": true, "Getpid": true,
	"Getppid": true, "Getuid": true, "Getwd": true, "Hostname": true,
	"IsExist": true, "IsNotExist": true, "IsPermission": true, "IsTimeout": true,
	"LookupEnv": true, "NewSyscallError": true, "Pipe": true, "SameFile": true,
	"Setenv": true, "TempDir": true, "Unsetenv": true, "UserCacheDir": true,
	"UserConfigDir": true, "UserHomeDir": true,

	// Reads a path, creates nothing.
	"DirFS": true, "Lstat": true, "Open": true, "ReadDir": true,
	"ReadFile": true, "Readlink": true, "Stat": true,
}

// containmentExempt names directories whose files create files and legitimately
// do not compose the path, each with the reason. Adding a name here is a
// deliberate act that shows up in review; forgetting a PathUnder call is not.
//
// An exemption is a claim about what a directory does, so the claim is checked
// rather than taken: TestExemptDirectoriesAreHandedTheirPaths fails if a file in
// one of these builds a path rather than being handed one, and the walk below
// fails if an entry names a directory that creates no files at all.
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
// collapsed. The second catches one that still sees cmd — most of the write
// sites — while seeing none of the generators, which is the half this gate is
// about.
const (
	writeSiteFloor         = 15
	unexemptWriteSiteFloor = 4
)

// osCreatesTheDirectory names the routines that create the DIRECTORY a later
// write lands in, rather than a file inside one. They are out of the population,
// and this is the reason rather than an oversight.
//
// PathUnder contains a file WITHIN a directory, so demanding it of the directory
// is a category error — there is no enclosing directory to contain it against,
// and the one the operator named through --out is the boundary itself. A
// directory is also not the thing the defect produced: what lands in it is, and
// every call that places a file there is in the population and must be contained.
// Creating a directory in the wrong place makes an empty directory; creating a
// file in the wrong place is the mode-0700 script this gate exists for.
var osCreatesTheDirectory = map[string]bool{"Mkdir": true, "MkdirAll": true}

// origin classifies the expression handed to a file-creating call.
type origin int

const (
	originContained origin = iota // came from PathUnder, directly or through a local wrapper
	originParameter               // a parameter of the enclosing function: deferred to its callers
	originHandedIn                // a bare identifier or field this file did not build
	originComposed                // built here: a call, or a concatenation
)

// writeCall is one file-creating call and the path expression it was given.
type writeCall struct {
	rel      string
	line     int
	name     string // as written, e.g. "os.WriteFile"
	fn       *ast.FuncDecl
	pathArg  ast.Expr
	pathName string // the identifier, when the argument is one
}

// classify decides where the path handed to a write came from.
func classify(w writeCall, contained, composedHere map[string]bool, wrappers map[string]bool) origin {
	if isContainedCall(w.pathArg, wrappers) {
		return originContained
	}
	if w.pathName == "" {
		if _, isSelector := w.pathArg.(*ast.SelectorExpr); isSelector {
			return originHandedIn
		}
		return originComposed
	}
	if contained[w.pathName] {
		return originContained
	}
	if composedHere[w.pathName] {
		return originComposed
	}
	if _, isParam := paramIndex(w.fn, w.pathName); isParam {
		return originParameter
	}
	return originHandedIn
}

// pathUnderWrappers names the functions in this file whose result is a PathUnder
// result. One level: a wrapper around a wrapper is not resolved, so it reports as
// composed rather than being assumed contained.
func pathUnderWrappers(file *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ret, isReturn := n.(*ast.ReturnStmt)
			if !isReturn {
				return true
			}
			for _, result := range ret.Results {
				if isPathUnderCall(result) {
					out[fn.Name.Name] = true
				}
			}
			return true
		})
	}
	return out
}

// isContainedCall reports whether e is a PathUnder call or a call to a local
// wrapper whose result is one.
func isContainedCall(e ast.Expr, wrappers map[string]bool) bool {
	if isPathUnderCall(e) {
		return true
	}
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return wrappers[fn.Name]
	case *ast.SelectorExpr:
		return wrappers[fn.Sel.Name]
	}
	return false
}

func TestEveryFileCreatingCallIsHandedAContainedPath(t *testing.T) {
	root := repoRoot(t)
	files := goSources(t, root)

	var writeSites, unexempt int
	// Obligations deferred to a caller: a write whose path is a parameter of the
	// enclosing function. Keyed by "pkgdir\x00func\x00paramIndex".
	deferred := map[string][]writeCall{}
	contained := map[string]map[string]bool{} // pkgdir -> identifier bound from PathUnder

	for _, f := range files {
		file, fset := parseFile(t, f.path)
		osNames, ok := importedAs(file, "os")
		if !ok {
			continue
		}
		if osNames["."] {
			t.Errorf("%s dot-imports os, so its calls carry no receiver and this gate cannot see them; import it under a name", f.rel)
			continue
		}

		pkgdir := filepath.Dir(f.rel)
		if contained[pkgdir] == nil {
			contained[pkgdir] = map[string]bool{}
		}
		for name := range boundFromPathUnder(file) {
			contained[pkgdir][name] = true
		}
		for name := range boundFromWrapper(file) {
			contained[pkgdir][name] = true
		}

		writes := fileCreatingCalls(file, fset, f.rel, osNames)
		writeSites += len(writes)
		if exemptDir(f.rel) != "" {
			continue
		}
		unexempt += len(writes)

		composedHere := composedIdentifiers(file)
		wrappers := pathUnderWrappers(file)

		for _, w := range writes {
			switch classify(w, contained[pkgdir], composedHere, wrappers) {
			case originContained:
				continue

			case originParameter:
				idx, _ := paramIndex(w.fn, w.pathName)
				key := pkgdir + "\x00" + w.fn.Name.Name + "\x00" + strconv.Itoa(idx)
				deferred[key] = append(deferred[key], w)

			case originHandedIn:
				// A path this file did not build and did not contain. Inside an
				// exempt directory that is the exemption's whole claim; outside
				// one it is a write whose destination nothing here decided.
				t.Errorf("%s:%d hands %s the path %q, which this package neither built nor contained; "+
					"compose it with fix.PathUnder, or add the directory to containmentExempt with the reason it does not need to",
					w.rel, w.line, w.name, w.pathName)

			case originComposed:
				t.Errorf("%s:%d hands %s a path it composed rather than one PathUnder produced; "+
					"a filename built from a value cloudgov read can name a file outside the directory the caller chose",
					w.rel, w.line, w.name)
			}
		}
	}

	// io/ioutil is refused outright rather than classified.
	//
	// It is deprecated, unused here, and its writers — WriteFile, TempFile,
	// TempDir — are a second population this gate would have to carry a second
	// read-only list for. Refusing the import is one rule with nothing to drift:
	// every route it offers has an os equivalent already in the population.
	for _, f := range files {
		file, _ := parseFile(t, f.path)
		if _, imported := importedAs(file, "io/ioutil"); imported {
			t.Errorf("%s imports io/ioutil, whose writers are outside this gate's population; "+
				"use the os equivalent, which is in it", f.rel)
		}
	}

	// One level of dataflow: a write whose path is a parameter is contained only
	// if EVERY call to that function in its package passes a contained
	// identifier. Deeper than one level is not resolved — a caller that itself
	// takes the path as a parameter fails here rather than being assumed safe,
	// which is the direction that cannot hide a write.
	resolveDeferred(t, root, files, deferred, contained)

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

func resolveDeferred(t *testing.T, root string, files []goSource, deferred map[string][]writeCall, contained map[string]map[string]bool) {
	t.Helper()
	if len(deferred) == 0 {
		return
	}

	// Every call in the module, keyed the same way, with the argument passed.
	type callSite struct {
		rel  string
		line int
		arg  ast.Expr
	}
	callers := map[string][]callSite{}
	for _, f := range files {
		file, fset := parseFile(t, f.path)
		pkgdir := filepath.Dir(f.rel)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			for i, arg := range call.Args {
				key := pkgdir + "\x00" + ident.Name + "\x00" + strconv.Itoa(i)
				if _, wanted := deferred[key]; wanted {
					callers[key] = append(callers[key], callSite{rel: f.rel, line: fset.Position(call.Pos()).Line, arg: arg})
				}
			}
			return true
		})
	}

	for key, writes := range deferred {
		parts := strings.Split(key, "\x00")
		pkgdir, fnName := parts[0], parts[1]
		sites := callers[key]
		if len(sites) == 0 {
			for _, w := range writes {
				t.Errorf("%s:%d hands %s a path taken from %s's parameters, and no call to %s in %s passes one; "+
					"nothing binds that path to PathUnder", w.rel, w.line, w.name, fnName, fnName, pkgdir)
			}
			continue
		}
		for _, site := range sites {
			if isPathUnderCall(site.arg) {
				continue
			}
			ident, ok := site.arg.(*ast.Ident)
			if ok && contained[pkgdir][ident.Name] {
				continue
			}
			for _, w := range writes {
				t.Errorf("%s:%d passes an uncontained path to %s, which hands it to %s at %s:%d; "+
					"the containment has to hold at every call site, not at the one that was written first",
					site.rel, site.line, fnName, w.name, w.rel, w.line)
			}
		}
	}
}

// An exemption says the directory is handed its paths rather than building them.
// That is a property of the code, so it is checked here instead of being carried
// by the sentence that claims it.
//
// Checked as "the write is handed a bare identifier that nothing in this file
// composed", rather than by looking for one spelling of composition: an earlier
// version searched for filepath.Join alone, which left string concatenation,
// path.Join and fmt.Sprintf with a separator all passing while the exemption's
// prose asserted otherwise.
func TestExemptDirectoriesAreHandedTheirPaths(t *testing.T) {
	root := repoRoot(t)
	files := goSources(t, root)

	covered := make(map[string]bool, len(containmentExempt))
	for _, f := range files {
		dir := exemptDir(f.rel)
		if dir == "" {
			continue
		}
		file, fset := parseFile(t, f.path)
		osNames, ok := importedAs(file, "os")
		if !ok {
			continue
		}
		writes := fileCreatingCalls(file, fset, f.rel, osNames)
		if len(writes) > 0 {
			covered[dir] = true
		}

		composedHere := composedIdentifiers(file)
		wrappers := pathUnderWrappers(file)
		for _, w := range writes {
			if classify(w, map[string]bool{}, composedHere, wrappers) != originComposed {
				continue
			}
			if w.pathName == "" {
				t.Errorf("%s:%d is under the exempt directory %q, whose exemption reads %q — "+
					"but it builds the path it writes to inline rather than being handed one",
					w.rel, w.line, dir, containmentExempt[dir])
				continue
			}
			if composedHere[w.pathName] {
				t.Errorf("%s:%d is under the exempt directory %q, whose exemption reads %q — "+
					"but %q is composed in this file. The exemption no longer describes it.",
					w.rel, w.line, dir, containmentExempt[dir], w.pathName)
			}
		}
	}

	for dir := range containmentExempt {
		if !covered[dir] {
			t.Errorf("containmentExempt names %q, which contains no file-creating call. "+
				"An exemption for a directory that writes nothing exempts nothing; remove it.", dir)
		}
	}
}

// composedIdentifiers returns the identifiers this file assigns from an
// expression that builds a path: any call, or any concatenation. Anything else
// — a bare identifier, a selector, a literal — is a value handed in.
func composedIdentifiers(file *ast.File) map[string]bool {
	out := map[string]bool{}
	record := func(names []ast.Expr, values []ast.Expr) {
		for i, lhs := range names {
			ident, ok := lhs.(*ast.Ident)
			if !ok || i >= len(values) {
				continue
			}
			switch values[i].(type) {
			case *ast.CallExpr, *ast.BinaryExpr:
				out[ident.Name] = true
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			record(node.Lhs, node.Rhs)
		case *ast.ValueSpec:
			var lhs []ast.Expr
			for _, name := range node.Names {
				lhs = append(lhs, name)
			}
			record(lhs, node.Values)
		}
		return true
	})
	return out
}

// fileCreatingCalls returns every call on the os package that is not named in
// osTakesNoPathOrOnlyReads, plus ioutil.WriteFile for the deprecated spelling.
func fileCreatingCalls(file *ast.File, fset *token.FileSet, rel string, osNames map[string]bool) []writeCall {
	var out []writeCall
	var stack []*ast.FuncDecl

	ast.Inspect(file, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok {
			stack = append(stack, fn)
			return true
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || !osNames[pkg.Name] {
			return true
		}
		if osTakesNoPathOrOnlyReads[sel.Sel.Name] || osCreatesTheDirectory[sel.Sel.Name] {
			return true
		}
		w := writeCall{
			rel:  rel,
			line: fset.Position(call.Pos()).Line,
			name: pkg.Name + "." + sel.Sel.Name,
		}
		if len(stack) > 0 {
			w.fn = stack[len(stack)-1]
		}
		if len(call.Args) > 0 {
			w.pathArg = call.Args[0]
			if ident, isIdent := call.Args[0].(*ast.Ident); isIdent {
				w.pathName = ident.Name
			}
		}
		out = append(out, w)
		return true
	})
	return out
}

// importedAs returns EVERY name the file refers to path by.
//
// Every, not the first: a file may import the same package twice, once plainly
// and once under an alias, and a gate that stops at the first match reads the
// aliased calls as belonging to some other package entirely. Returning one name
// let os.WriteFile be checked while goos.CreateTemp beside it was invisible.
//
// The repo's own scripts/check-context.sh self-tests that it catches a detached
// context through an aliased import; a source-level gate here is held to the
// same bar.
func importedAs(file *ast.File, path string) (map[string]bool, bool) {
	names := map[string]bool{}
	for _, imp := range file.Imports {
		value, err := strconv.Unquote(imp.Path.Value)
		if err != nil || value != path {
			continue
		}
		if imp.Name == nil {
			names[filepath.Base(path)] = true
			continue
		}
		switch imp.Name.Name {
		case "_":
			// Imported for its side effects; no calls to find.
		case ".":
			// A dot import puts the package's names in file scope, so a call has
			// no receiver to match on. Refused rather than skipped: the gate
			// cannot see writes in such a file, and silence there is the failure
			// this whole check exists to avoid.
			names["."] = true
		default:
			names[imp.Name.Name] = true
		}
	}
	return names, len(names) > 0
}

// boundFromPathUnder returns the identifiers this file assigns from an
// expression containing a PathUnder call.
func boundFromPathUnder(file *ast.File) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		var fromPathUnder bool
		for _, rhs := range assign.Rhs {
			if isPathUnderCall(rhs) {
				fromPathUnder = true
			}
		}
		if !fromPathUnder {
			return true
		}
		for _, lhs := range assign.Lhs {
			if ident, isIdent := lhs.(*ast.Ident); isIdent && ident.Name != "err" && ident.Name != "_" {
				out[ident.Name] = true
			}
		}
		return true
	})
	return out
}

// boundFromWrapper returns the identifiers assigned from a call to a local
// function whose result is a PathUnder result.
func boundFromWrapper(file *ast.File) map[string]bool {
	wrappers := pathUnderWrappers(file)
	out := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		var fromWrapper bool
		for _, rhs := range assign.Rhs {
			if isContainedCall(rhs, wrappers) {
				fromWrapper = true
			}
		}
		if !fromWrapper {
			return true
		}
		for _, lhs := range assign.Lhs {
			if ident, isIdent := lhs.(*ast.Ident); isIdent && ident.Name != "err" && ident.Name != "_" {
				out[ident.Name] = true
			}
		}
		return true
	})
	return out
}

func isPathUnderCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "PathUnder"
	case *ast.SelectorExpr:
		return fn.Sel.Name == "PathUnder"
	}
	return false
}

func paramIndex(fn *ast.FuncDecl, name string) (int, bool) {
	if fn == nil || fn.Type.Params == nil {
		return 0, false
	}
	i := 0
	for _, field := range fn.Type.Params.List {
		for _, ident := range field.Names {
			if ident.Name == name {
				return i, true
			}
			i++
		}
		if len(field.Names) == 0 {
			i++
		}
	}
	return 0, false
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

func parseFile(t *testing.T, path string) (*ast.File, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return file, fset
}

// goSources returns every non-test Go file under the module root.
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
	sort.Strings(dirs)
	return dirs
}

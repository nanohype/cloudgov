package fix

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Where the containment claim lives, and why it is not here.
//
// "No remediation writer places an entry outside the directory it was given" is
// a claim about where a file ends up. This file used to assert it by reading the
// source: enumerating the calls that create files, classifying the expression
// handed to each, and resolving a level of dataflow to the callers. Each round of
// that bought exactly one more round. A variable spelled like a contained one
// passed, because the contained set was names with no scope. A rename passed,
// because only the first argument was classified and the destination is the
// second. A helper in another package passed, because the caller index saw only
// unqualified calls. `var writeOut = os.WriteFile` passed, because the call was
// no longer a selector. A subprocess passed, because it is not the os package at
// all. The source has infinite spellings and a reader learns them one defect at
// a time.
//
// TestNoRemediationWriterPlacesAnEntryOutsideItsOutputDirectory in
// internal/integration runs each writer against a report that names an escape
// and walks the filesystem afterwards. It does not care which spelling was used:
// the subprocess escape this file reported clean fails there.
//
// What is left here is the one property that genuinely is about the source.

// A file-creating routine reached through io/ioutil would be a write no
// behavioural driver was written for, because nothing here uses that package and
// no driver would think to.
//
// This IS a question about the source — does any file import it — rather than
// about where a file lands, which is why it is answered by reading and not by
// running. The package is deprecated, every route it offers has an os
// equivalent, and refusing the import is one rule with nothing to drift.
func TestNoFileImportsIoutil(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	var read int
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
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
		read++

		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Errorf("parse %s: %v", path, parseErr)
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		for _, imp := range file.Imports {
			value, unquoteErr := strconv.Unquote(imp.Path.Value)
			if unquoteErr == nil && value == "io/ioutil" {
				t.Errorf("%s imports io/ioutil; use the os equivalent, which the behavioural "+
					"containment drivers in internal/integration already run", filepath.ToSlash(rel))
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", root, walkErr)
	}

	// A floor well under the real count. A walk that reached nothing reports every
	// file as clean, which is the reading that looks like a clean tree.
	const sourceFileFloor = 80
	if read < sourceFileFloor {
		t.Fatalf("read %d non-test Go file(s), under the floor of %d — the walk collapsed rather than the tree shrinking", read, sourceFileFloor)
	}
}

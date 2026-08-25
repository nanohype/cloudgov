package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestOutputFormatsResolve(t *testing.T) {
	for _, tc := range []struct {
		name    string
		formats outputFormats
		input   string
		want    string
		wantErr bool
	}{
		{"exact", tableJSONSARIF, "sarif", "sarif", false},
		{"uppercase", tableJSONSARIF, "SARIF", "sarif", false},
		{"padded", tableJSON, "  json  ", "json", false},
		{"default", tableJSON, "table", "table", false},
		{"typo", tableJSON, "jsonn", "", true},
		{"empty", tableJSON, "", "", true},
		{"format the command cannot produce", tableJSON, "sarif", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.formats.resolve(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolve(%q) accepted a format this command does not render", tc.input)
				}
				if !strings.Contains(err.Error(), strings.Join(tc.formats, ", ")) {
					t.Errorf("error does not name the accepted formats: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("resolve(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// The flag's help text is rendered from the set it validates against, so the two
// cannot disagree. This pins that they are one value rather than two kept in
// step by hand.
func TestUsageTextIsRenderedFromTheAcceptedSet(t *testing.T) {
	for _, formats := range []outputFormats{tableJSON, tableJSONSARIF} {
		usage := formats.usage()
		for _, name := range formats {
			if !strings.Contains(usage, name) {
				t.Errorf("usage %q does not name the accepted format %q", usage, name)
			}
		}
		parsed, ok := outputFormatFor(&cobra.Command{
			Use: "probe",
			Run: func(*cobra.Command, []string) {},
		})
		if ok || parsed != nil {
			t.Error("a command with no --output flag reported a format set")
		}
	}
}

// walkCommands yields every runnable command in the tree, so this file's checks
// measure the commands that exist rather than a list someone maintained.
func walkCommands(root *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	var visit func(*cobra.Command)
	visit = func(c *cobra.Command) {
		if c.Runnable() {
			out = append(out, c)
		}
		for _, sub := range c.Commands() {
			visit(sub)
		}
	}
	visit(root)
	return out
}

// Every --output flag in the tree rejects a format it cannot render.
//
// The defect this closes: each handler switched on the raw flag string with a
// `default:` arm that rendered a table, so `--output sarif` on a command that
// emits none wrote an ANSI table into results.sarif and exited 0. A CI step that
// redirects to a file and checks the exit code reads that as a successful scan.
//
// Enumerating the tree rather than a list is what makes this a class: a command
// added later is covered by construction.
func TestEveryOutputFlagRejectsAnUnrenderableFormat(t *testing.T) {
	commands := walkCommands(rootCmd)
	if len(commands) == 0 {
		t.Fatal("the command tree is empty; this check would pass vacuously")
	}

	checked := 0
	for _, c := range commands {
		formats, ok := outputFormatFor(c)
		if !ok {
			continue
		}
		checked++
		t.Run(strings.ReplaceAll(c.CommandPath(), " ", "_"), func(t *testing.T) {
			if len(formats) == 0 {
				t.Fatalf("%s declares an --output flag naming no formats", c.CommandPath())
			}
			if _, err := formats.resolve("no-such-format"); err == nil {
				t.Errorf("%s accepts an unrenderable format", c.CommandPath())
			}
			// Everything the help text names must actually resolve, or the flag
			// advertises a format the command refuses.
			for _, name := range formats {
				if _, err := formats.resolve(name); err != nil {
					t.Errorf("%s advertises %q but rejects it: %v", c.CommandPath(), name, err)
				}
			}
		})
	}

	if checked == 0 {
		t.Fatal("no command in the tree declares an --output flag; the enumeration is broken, not the tree")
	}
}

// A SARIF-capable command is one whose renderer produces SARIF. The set a
// command declares is therefore a claim about what internal/output can emit for
// it, and AGENTS.md repeats that claim to agents — so the two are pinned here.
func TestSARIFCapabilityMatchesTheDocumentedSet(t *testing.T) {
	// AGENTS.md: "SARIF is emitted by iam, storage, certs, secrets, audit, k8s,
	// lambda, platform, compliance, and drift."
	documented := map[string]bool{
		"cloudgov iam scan":       true,
		"cloudgov storage audit":  true,
		"cloudgov certs":          true,
		"cloudgov secrets scan":   true,
		"cloudgov audit":          true,
		"cloudgov k8s rbac":       true,
		"cloudgov lambda audit":   true,
		"cloudgov platform audit": true,
		"cloudgov compliance":     true,
		"cloudgov drift":          true,
	}

	seen := map[string]bool{}
	for _, c := range walkCommands(rootCmd) {
		formats, ok := outputFormatFor(c)
		if !ok {
			continue
		}
		emitsSARIF := false
		for _, name := range formats {
			if name == "sarif" {
				emitsSARIF = true
			}
		}
		path := c.CommandPath()
		if emitsSARIF {
			seen[path] = true
			if !documented[path] {
				t.Errorf("%s accepts --output sarif but AGENTS.md does not list it as a SARIF emitter", path)
			}
			continue
		}
		if documented[path] {
			t.Errorf("AGENTS.md lists %s as a SARIF emitter but its --output flag refuses sarif", path)
		}
	}
	for path := range documented {
		if !seen[path] {
			t.Errorf("AGENTS.md lists %s as a SARIF emitter but no such command declares an --output flag", path)
		}
	}
}

// README: "All formats can be written to a file with `--output-file`." That is a
// claim about every command that renders a format, so it holds only while none
// of them is missing the flag. A command that renders to stdout alone forces a
// shell redirect, which mixes the report with anything the command writes to
// stderr and produces a file whose contents depend on the terminal.
func TestEveryRenderingCommandCanWriteToAFile(t *testing.T) {
	checked := 0
	for _, c := range walkCommands(rootCmd) {
		if _, ok := outputFormatFor(c); !ok {
			continue
		}
		checked++
		if c.Flags().Lookup("output-file") == nil && c.InheritedFlags().Lookup("output-file") == nil {
			t.Errorf("%s declares --output but no --output-file", c.CommandPath())
		}
	}
	if checked == 0 {
		t.Fatal("no command declares an --output flag; the enumeration is broken, not the tree")
	}
}

// Every command the tree exposes has a README reference section.
//
// CONTRIBUTING.md and CLAUDE.md both make documenting a new command a required
// step, and three shipped commands had no section anyway — a step in a checklist
// is not a mechanism. This is the mechanism: a command added without a section
// fails the build rather than shipping undiscoverable.
//
// Hidden commands are exempt by construction, since a command the help output
// does not list is not one a reader is being pointed at.
func TestEveryCommandHasAREADMESection(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	text := string(readme)

	headings := regexp.MustCompile("(?m)^### `cloudgov [^`]*`").FindAllString(text, -1)
	if len(headings) == 0 {
		t.Fatal("README declares no command sections; this check would pass vacuously")
	}

	documented := map[string]bool{}
	for _, h := range headings {
		// "### `cloudgov drift <tfstate>` — ..." → "cloudgov drift". The argument
		// placeholder is part of the heading's usage line, not part of the name.
		name := strings.Trim(strings.TrimPrefix(h, "### "), "`")
		if i := strings.Index(name, " <"); i >= 0 {
			name = name[:i]
		}
		documented[name] = true
	}

	// A section on a group command documents the group. `cloudgov baseline`
	// covers save/list/delete, which are one workflow rather than three commands
	// a reader looks up separately.
	covered := func(path string) bool {
		for p := path; p != ""; {
			if documented[p] {
				return true
			}
			i := strings.LastIndex(p, " ")
			if i < 0 {
				return false
			}
			p = p[:i]
			if p == "cloudgov" {
				return false
			}
		}
		return false
	}

	checked := 0
	for _, c := range walkCommands(rootCmd) {
		if c.Hidden || c.CommandPath() == "cloudgov" {
			continue
		}
		checked++
		if !covered(c.CommandPath()) {
			t.Errorf("%s is registered and visible but has no README section", c.CommandPath())
		}
	}
	if checked == 0 {
		t.Fatal("the command tree exposes nothing; the enumeration is broken, not the tree")
	}

	// The other direction: a section for a command that no longer exists points a
	// reader at something that will fail with "unknown command". A group command
	// is live when it is registered, whether or not it runs on its own.
	live := map[string]bool{}
	var record func(*cobra.Command)
	record = func(c *cobra.Command) {
		live[c.CommandPath()] = true
		for _, sub := range c.Commands() {
			record(sub)
		}
	}
	record(rootCmd)
	for name := range documented {
		if !live[name] {
			t.Errorf("README documents %q, which the command tree does not expose", name)
		}
	}
}

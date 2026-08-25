package cmd

import (
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

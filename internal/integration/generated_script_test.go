package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/network"
	orphanscanner "github.com/nanohype/cloudgov/internal/orphans"
	"github.com/nanohype/cloudgov/internal/storage"
)

// The invariant every generated script holds:
//
//	Every line is blank, a comment, or a command the generator put there. The
//	report supplies values that appear in those lines. It does not supply extra
//	lines.
//
// "The generator put there" is the honest half. For orphans that means a command
// cloudgov composed from an allowlist of kinds, so the report chooses none of it.
// For storage and network the report's `remediation` field IS the command by
// documented contract — the scan writes it and remediate copies it verbatim, so
// a multi-line remediation is as many lines as the report wrote. The invariant
// for those two is that the report supplies no line OTHER than that field's
// contents. The security delta is nil, since a semicolon on one line carries the
// same power; the point is that the sentence says what the code does.
// README.md tells an operator the same thing, which is where they will look.
//
// Containing the path was half of the defect. `cloudgov remediate` reads a report
// an operator received, and the same report fills the `#` banner above each
// command — so a newline in any of those values ended the comment and opened a
// line of its own, in a file written 0700, above a command the tool composed.
// Closing only the path moved the report's choice inside --out rather than
// removing it.
//
// Asserted here rather than in each generator's own package because it is one
// invariant, and three copies of it drift. This package already imports all
// three.
//
// The hostile value is placed in EVERY string field the caller controls, not in
// the one that was reported: the defect was a property of interpolating report
// text into a script, and any field reaching a banner line carries it.

// injected is what the report tries to make the script do. It is checked for at
// the start of a line, because a comment line quoting it is the containment
// working rather than failing.
const injected = "aws s3 rb s3://victim-bucket --force"

// hostile wraps a value so that it ends its line and starts another.
func hostile(field string) string {
	return field + "\n" + injected
}

func TestGeneratedScriptsTakeNoLinesFromTheReport(t *testing.T) {
	tests := []struct {
		name string
		// generate writes the scripts for one hostile report into outDir and
		// returns the files written.
		generate func(outDir string) ([]string, error)
		// commands is how many non-comment lines the generator was asked to
		// emit, so a run that drops the injected line by dropping everything is
		// a failure rather than a pass.
		commands int
	}{
		{
			name: "storage",
			generate: func(outDir string) ([]string, error) {
				return storage.WriteFixScripts([]cloud.BucketFinding{{
					Severity: cloud.SeverityCritical,
					Type:     cloud.BucketPublicAccess,
					Provider: "aws",
					Bucket:   hostile("b"),
					Region:   hostile("us-east-1"),
					Detail:   hostile("bucket is public"),
					// The Remediation IS the command for this generator, by its
					// documented contract, so it is the one field left alone:
					// a report that supplies a command is this command's input,
					// and the invariant is about lines the report was not asked
					// for.
					Remediation: "aws s3api put-public-access-block --bucket b",
				}}, outDir)
			},
			commands: 1,
		},
		{
			name: "network",
			generate: func(outDir string) ([]string, error) {
				return network.WriteFixScripts([]cloud.NetworkFinding{{
					Severity:    cloud.SeverityCritical,
					Type:        cloud.NetworkAdminPortOpen,
					Provider:    "aws",
					Resource:    hostile("sg-1"),
					Region:      hostile("us-east-1"),
					Protocol:    hostile("tcp"),
					Port:        hostile("22"),
					CIDR:        hostile("0.0.0.0/0"),
					Detail:      hostile("ssh open to the internet"),
					Remediation: "aws ec2 revoke-security-group-ingress --group-id sg-1",
				}}, outDir)
			},
			commands: 1,
		},
		{
			name: "orphans",
			generate: func(outDir string) ([]string, error) {
				// The worst case in the tree: this generator composes its own
				// command from an allowlist of kinds, so every line it emits is
				// one the tool chose — and the file is a list of deletes.
				return orphanscanner.WriteFixScripts([]cloud.OrphanResource{{
					Kind:     cloud.OrphanDisk,
					ID:       "vol-1",
					Name:     hostile("old-disk"),
					Region:   hostile("us-east-1"),
					Provider: "aws",
					Detail:   hostile("unattached"),
				}}, outDir)
			},
			commands: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outDir := t.TempDir()
			files, err := tc.generate(outDir)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if len(files) == 0 {
				t.Fatal("no script was written; this test would pass on an empty tree")
			}

			for _, path := range files {
				body, readErr := os.ReadFile(path) // #nosec G304 -- path is what the generator under test just returned
				if readErr != nil {
					t.Fatalf("read %s: %v", path, readErr)
				}
				script := string(body)

				if !strings.Contains(script, injected) {
					t.Fatalf("%s does not contain the hostile value at all; the fixture is not exercising the interpolation it names:\n%s",
						filepath.Base(path), script)
				}

				var commandLines []string
				for _, line := range strings.Split(script, "\n") {
					trimmed := strings.TrimSpace(line)
					if trimmed == "" || strings.HasPrefix(trimmed, "#") {
						continue
					}
					commandLines = append(commandLines, line)
					if strings.HasPrefix(trimmed, injected) {
						t.Errorf("%s: the report placed a line of its own in a generated script:\n    %s",
							filepath.Base(path), line)
					}
				}

				// A generator that emitted nothing would satisfy the check above,
				// so the count is asserted too. The shebang is a comment by this
				// count, so `set -euo pipefail` is the one preamble line left.
				// The fixture's remediation is deliberately one line, so this
				// counts lines the report did not ask for; a multi-line
				// remediation legitimately raises the total for storage and
				// network, which is why it is not the hostile field here.
				const preamble = 1
				if got := len(commandLines) - preamble; got != tc.commands {
					t.Errorf("%s emitted %d command line(s), want %d:\n%s",
						filepath.Base(path), got, tc.commands, script)
				}
			}
		})
	}
}

package output

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/audit"
	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/compliance"
)

// SARIF is the one output that outlives the process that produced it.
//
// The other formats carry the unread record in ways a reader cannot miss: the
// JSON writers take it as a parameter, the table renderer prints a note, and the
// command exits 3. SARIF is uploaded, ingested, and read weeks later by someone
// who never saw any of those. A partial scan rendered there as a clean report is
// the failure with the longest half life, so every writer carries it and the run
// is marked unsuccessful.
func TestEverySARIFWriterCarriesTheIncompleteRecord(t *testing.T) {
	const unread = "ec2:DescribeInstances in eu-west-1: AccessDenied"

	writers := map[string]func(*bytes.Buffer, []string) error{
		"WriteSARIF": func(b *bytes.Buffer, inc []string) error {
			return WriteSARIF(b, nil, "v", inc)
		},
		"WriteStorageSARIF": func(b *bytes.Buffer, inc []string) error {
			return WriteStorageSARIF(b, nil, "v", inc)
		},
		"WriteSecretsSARIF": func(b *bytes.Buffer, inc []string) error {
			return WriteSecretsSARIF(b, nil, "v", inc)
		},
		"WriteK8sSARIF": func(b *bytes.Buffer, inc []string) error {
			return WriteK8sSARIF(b, nil, "v", inc)
		},
		"WriteLambdaSARIF": func(b *bytes.Buffer, inc []string) error {
			return WriteLambdaSARIF(b, nil, "v", inc)
		},
		"WriteComplianceSARIF": func(b *bytes.Buffer, inc []string) error {
			return WriteComplianceSARIF(b, compliance.ComplianceReport{}, "v", inc)
		},
		"WriteDriftSARIF": func(b *bytes.Buffer, inc []string) error {
			return WriteDriftSARIF(b, nil, "v", inc)
		},
		"WritePlatformSARIF": func(b *bytes.Buffer, inc []string) error {
			return WritePlatformSARIF(b, nil, "v", inc)
		},
		"WriteCertsSARIF": func(b *bytes.Buffer, inc []string) error {
			return WriteCertsSARIF(b, nil, "v", inc)
		},
		"WriteAuditSARIF": func(b *bytes.Buffer, inc []string) error {
			return WriteAuditSARIF(b, &audit.Report{}, "v", inc)
		},
	}

	// The population comes from the source, not from the map above. A writer
	// added without an entry here fails rather than joining the ones nothing
	// checks.
	declared := declaredSARIFWriters(t)
	if len(declared) == 0 {
		t.Fatal("no SARIF writers found in the package source; this test would pass vacuously")
	}
	for _, name := range declared {
		if _, ok := writers[name]; !ok {
			t.Errorf("%s is a SARIF writer with no incomplete-contract case here; "+
				"a writer nothing exercises is a format that can silently drop the record", name)
		}
	}

	for name, write := range writers {
		t.Run(name+"/partial", func(t *testing.T) {
			var buf bytes.Buffer
			if err := write(&buf, []string{unread}); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			var log struct {
				Runs []struct {
					Invocations []struct {
						ExecutionSuccessful        bool `json:"executionSuccessful"`
						ToolExecutionNotifications []struct {
							Level   string `json:"level"`
							Message struct {
								Text string `json:"text"`
							} `json:"message"`
						} `json:"toolExecutionNotifications"`
					} `json:"invocations"`
				} `json:"runs"`
			}
			if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
				t.Fatalf("%s produced unparseable SARIF: %v", name, err)
			}
			if len(log.Runs) != 1 || len(log.Runs[0].Invocations) != 1 {
				t.Fatalf("%s: want exactly one run with one invocation, got %d run(s)", name, len(log.Runs))
			}
			inv := log.Runs[0].Invocations[0]
			if inv.ExecutionSuccessful {
				t.Errorf("%s reported executionSuccessful over a scan that could not read %q; "+
					"a consumer cannot tell this from a clean account", name, unread)
			}
			if len(inv.ToolExecutionNotifications) != 1 ||
				!strings.Contains(inv.ToolExecutionNotifications[0].Message.Text, "AccessDenied") {
				t.Errorf("%s did not attach the unread probe as a notification: %+v", name, inv.ToolExecutionNotifications)
			}
		})

		t.Run(name+"/complete", func(t *testing.T) {
			var buf bytes.Buffer
			if err := write(&buf, nil); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			// The other direction on the same writer: a complete scan must say so
			// rather than omit the field, because an absent invocations array and a
			// successful one are different claims.
			if !bytes.Contains(buf.Bytes(), []byte(`"executionSuccessful": true`)) {
				t.Errorf("%s did not mark a complete scan successful; an absent record is not the same claim as an empty one", name)
			}
			if !bytes.Contains(buf.Bytes(), []byte(`"toolExecutionNotifications": []`)) {
				t.Errorf("%s omitted the notifications array on a complete scan; null and empty are different answers", name)
			}
		})
	}
}

// declaredSARIFWriters enumerates the exported SARIF writers from the package
// source, so the population is derived rather than restated.
func declaredSARIFWriters(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sarif.go", nil, 0)
	if err != nil {
		t.Fatalf("parse sarif.go: %v", err)
	}
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name == nil {
			continue
		}
		name := fn.Name.Name
		if !strings.HasPrefix(name, "Write") || !strings.HasSuffix(name, "SARIF") {
			continue
		}
		out = append(out, name)
	}
	return out
}

// The detector must be able to find a writer, or the enumeration above proves
// nothing about the map it checks.
func TestSARIFWriterEnumerationFindsWriters(t *testing.T) {
	got := declaredSARIFWriters(t)
	if len(got) < 5 {
		t.Fatalf("the writer enumeration found %d writer(s); it has stopped matching the source", len(got))
	}
	var seen bool
	for _, n := range got {
		if n == "WritePlatformSARIF" {
			seen = true
		}
	}
	if !seen {
		t.Error("the enumeration missed WritePlatformSARIF, a writer that exists")
	}
}

var _ = cloud.SeverityInfo

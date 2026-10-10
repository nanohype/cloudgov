package output

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/audit"
	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/compliance"
)

// tableRenderers drives every table renderer with input that reaches its
// styled paths: a header, a severity cell, a summary line.
//
// lipgloss v2's Style.Render always emits 24-bit escapes; v1 dropped them when
// stdout was not a terminal. So the decision about colour now belongs to the
// writer, and a renderer that forgets to route through styled() writes escape
// codes into a piped table, a CI log, and the --output-file artifact a reader
// keeps. Nothing fails at build time when that happens, which is why the list
// is checked against the package below rather than trusted.
var tableRenderers = map[string]func(io.Writer){
	"AuditReport": func(w io.Writer) {
		AuditReport(w, &audit.Report{
			Duration: "1s",
			IAM:      []cloud.Finding{{Severity: cloud.SeverityCritical, Type: cloud.FindingAdminAccess, Provider: "aws", Principal: &cloud.Principal{Name: "x"}}},
			Storage:  []cloud.BucketFinding{{Severity: cloud.SeverityHigh, Provider: "aws", Bucket: "b"}},
			Summary:  audit.ReportSummary{TotalFindings: 2, DomainsRun: 2, BySeverity: map[string]int{"CRITICAL": 1, "HIGH": 1}},
		})
	},
	"BucketFindings": func(w io.Writer) {
		BucketFindings(w, []cloud.BucketFinding{{Severity: cloud.SeverityCritical, Type: cloud.BucketPublicAccess, Provider: "aws", Bucket: "leaky"}})
	},
	"CertFindings": func(w io.Writer) {
		CertFindings(w, []cloud.CertFinding{{Severity: cloud.SeverityCritical, Status: cloud.CertExpired, Provider: "aws", Domain: "gone.example.com"}})
	},
	"CompareTable": func(w io.Writer) {
		CompareTable(w, CompareResult{
			New:      []CompareFindingType{{Domain: "iam", ResourceID: "a"}},
			Resolved: []CompareFindingType{{Domain: "iam", ResourceID: "b"}},
		})
	},
	"ComplianceReport": func(w io.Writer) {
		ComplianceReport(w, compliance.ComplianceReport{
			Benchmark: "CIS AWS v3",
			Results: []compliance.ControlResult{
				{Control: compliance.Control{ID: "1.1"}, Status: compliance.StatusPass},
				{Control: compliance.Control{ID: "1.2"}, Status: compliance.StatusFail},
			},
			Summary: compliance.ComplianceSummary{Passed: 1, Failed: 1, Total: 2},
		})
	},
	"CostDiffs": func(w io.Writer) {
		CostDiffs(w, []cloud.CostDiff{{Provider: "aws", Entries: []cloud.CostDiffEntry{{Service: "EC2", Before: 100, After: 150, Delta: 50, PctChange: 50}}}})
	},
	"DriftResults": func(w io.Writer) {
		DriftResults(w, []cloud.DriftResult{{ResourceType: "aws_security_group", ResourceID: "sg-1", Status: cloud.DriftModified}})
	},
	"IAMFindings": func(w io.Writer) {
		IAMFindings(w, []cloud.Finding{{Severity: cloud.SeverityCritical, Type: cloud.FindingAdminAccess, Provider: "aws", Principal: &cloud.Principal{Name: "admin"}}}, 1)
	},
	"IncompleteNote": func(w io.Writer) {
		IncompleteNote(w, []string{"us-west-2: denied"})
		IncompleteNote(w, nil)
	},
	"InventoryResources": func(w io.Writer) {
		InventoryResources(w, []cloud.InventoryResource{{Type: "ec2:instance", ID: "i-1", Provider: "aws"}})
	},
	"K8sFindings": func(w io.Writer) {
		K8sFindings(w, []cloud.K8sFinding{{Severity: cloud.SeverityCritical, Kind: "ClusterRole", Name: "admin"}})
	},
	"LambdaPolicyFindings": func(w io.Writer) {
		LambdaPolicyFindings(w, []cloud.LambdaPolicyFinding{{Severity: cloud.SeverityCritical, Provider: "aws", FunctionName: "fn"}})
	},
	"NetworkFindings": func(w io.Writer) {
		NetworkFindings(w, []cloud.NetworkFinding{{Severity: cloud.SeverityCritical, Type: cloud.NetworkAdminPortOpen, Provider: "aws", Resource: "sg-1"}})
	},
	"OrphanResources": func(w io.Writer) {
		OrphanResources(w, []cloud.OrphanResource{{Kind: cloud.OrphanDisk, ID: "vol-1", Provider: "aws", MonthlyCost: 10}})
	},
	"PlatformFindings": func(w io.Writer) {
		PlatformFindings(w, []cloud.PlatformFinding{{Severity: cloud.SeverityCritical, Platform: "p"}})
	},
	"QuotaUsages": func(w io.Writer) {
		QuotaUsages(w, []cloud.QuotaUsage{{Provider: "aws", Service: "EC2", QuotaName: "EIPs", Used: 5, Limit: 5, Utilization: 100}})
	},
	"RepoFindings": func(w io.Writer) {
		RepoFindings(w, []cloud.RepoFinding{{Severity: cloud.SeverityCritical}})
	},
	"SecretFindings": func(w io.Writer) {
		SecretFindings(w, []cloud.SecretFinding{{Severity: cloud.SeverityCritical, Provider: "aws", Resource: "lambda:fn"}})
	},
	"TagFindings": func(w io.Writer) {
		TagFindings(w, []cloud.TagFinding{{Severity: cloud.SeverityMedium, Provider: "aws", ResourceID: "i-1", MissingTags: []string{"owner"}}})
	},
}

// clearColorEnv removes every variable that can force colour onto a writer that
// is not a terminal, so the result does not depend on the shell running it.
func clearColorEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"CLICOLOR_FORCE", "CLICOLOR", "NO_COLOR", "COLORTERM", "TERM"} {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
}

// A table written anywhere but a terminal must be plain text. A bytes.Buffer
// stands in for a pipe, a CI log, and the --output-file artifact alike: none is
// a terminal, so none may carry an escape sequence.
func TestRenderersEmitNoEscapesToNonTerminal(t *testing.T) {
	clearColorEnv(t)
	for name, render := range tableRenderers {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			render(&buf)
			if buf.Len() == 0 {
				t.Fatal("renderer wrote nothing, so this check proves nothing")
			}
			if i := bytes.IndexByte(buf.Bytes(), 0x1b); i >= 0 {
				end := min(i+24, buf.Len())
				t.Errorf("escape sequence in non-terminal output at byte %d: %q", i, buf.Bytes()[i:end])
			}
		})
	}
}

// The other half: colour still reaches a writer that asks for it. Without this
// the test above passes on a renderer whose styles were deleted outright.
func TestRenderersKeepColourWhenForced(t *testing.T) {
	clearColorEnv(t)
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("TERM", "xterm-256color")
	var buf bytes.Buffer
	tableRenderers["IAMFindings"](&buf)
	if !bytes.Contains(buf.Bytes(), []byte("\x1b[")) {
		t.Errorf("CLICOLOR_FORCE=1 produced no colour:\n%s", buf.String())
	}
}

// Every exported table renderer in this package is in tableRenderers. A
// renderer is an exported function whose first parameter is an io.Writer and
// whose name does not start with Write (those are the JSON and SARIF writers,
// which carry no styles).
func TestTableRenderersListIsComplete(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var found []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || strings.HasPrefix(fn.Name.Name, "Write") {
				continue
			}
			params := fn.Type.Params.List
			if len(params) == 0 {
				continue
			}
			if sel, ok := params[0].Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Writer" {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "io" {
					found = append(found, fn.Name.Name)
				}
			}
		}
	}
	if len(found) == 0 {
		t.Fatal("found no renderers; the scan is broken, not the package")
	}
	exported := make(map[string]bool, len(found))
	for _, name := range found {
		exported[name] = true
		if _, ok := tableRenderers[name]; !ok {
			t.Errorf("%s renders a table but is not in tableRenderers, so nothing checks it emits plain text off a terminal", name)
		}
	}
	for name := range tableRenderers {
		if !exported[name] {
			t.Errorf("tableRenderers lists %s, which is no longer an exported renderer", name)
		}
	}
}

// Off a terminal the columns line up. tabwriter measures a cell as the bytes it
// is handed, so if the escapes are stripped after it has measured, every styled
// cell is padded for codes that never reach the reader and the columns drift by
// a different amount per row.
func TestPlainTablesStayAligned(t *testing.T) {
	clearColorEnv(t)
	var buf bytes.Buffer
	CompareTable(&buf, CompareResult{
		New:      []CompareFindingType{{Domain: "iam", ResourceID: "a"}},
		Resolved: []CompareFindingType{{Domain: "iam", ResourceID: "b"}},
	})
	lines := strings.Split(buf.String(), "\n")
	col := strings.Index(lines[0], "DOMAIN")
	if col < 0 {
		t.Fatalf("no header in:\n%s", buf.String())
	}
	for _, l := range lines[1:3] {
		if got := strings.Index(l, "iam"); got != col {
			t.Errorf("DOMAIN column at %d in the header but %d in %q", col, got, l)
		}
	}
}

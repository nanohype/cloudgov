package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectType(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "audit",
			data: `{"summary": {"total_findings": 5}, "duration": "1.5s"}`,
			want: "audit",
		},
		{
			name: "iam",
			data: `{"findings": [], "principals_scanned": 5}`,
			want: "iam",
		},
		{
			name: "cost",
			data: `{"diffs": []}`,
			want: "cost",
		},
		{
			name: "orphans",
			data: `{"resources": [], "estimated_monthly_usd": 0}`,
			want: "orphans",
		},
		{
			name: "unknown",
			data: `{"foo": "bar"}`,
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectType([]byte(tt.data))
			if got != tt.want {
				t.Errorf("DetectType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerate_IAM(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "iam.json")
	outputFile := filepath.Join(dir, "report.html")

	input := `{
		"findings": [
			{
				"severity": "HIGH",
				"type": "ADMIN_ACCESS",
				"provider": "aws",
				"resource": "arn:aws:iam::123:role/admin",
				"detail": "has admin access"
			}
		],
		"total": 1,
		"principals_scanned": 5
	}`
	if err := os.WriteFile(inputFile, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	err := Generate(Options{
		InputFile:  inputFile,
		OutputFile: outputFile,
		ReportType: "auto",
		Version:    "v1.0.0-test",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	html, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}

	content := string(html)
	checks := []string{
		"CloudGov IAM Report",
		"ADMIN_ACCESS",
		"has admin access",
		"v1.0.0-test",
	}
	for _, check := range checks {
		if !strings.Contains(content, check) {
			t.Errorf("HTML missing expected string: %q", check)
		}
	}
}

func TestGenerate_Audit(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "audit.json")
	outputFile := filepath.Join(dir, "report.html")

	input := `{
		"summary": {"total_findings": 2, "by_severity": {"HIGH": 1, "MEDIUM": 1}, "by_domain": {"iam": 1, "storage": 1}},
		"duration": "2.5s",
		"iam": [{"severity": "HIGH", "type": "ADMIN_ACCESS", "provider": "aws", "resource": "role/admin", "detail": "admin"}],
		"storage": [{"severity": "MEDIUM", "type": "PUBLIC_ACCESS", "provider": "aws", "bucket": "pub", "detail": "public"}]
	}`
	if err := os.WriteFile(inputFile, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	err := Generate(Options{
		InputFile:  inputFile,
		OutputFile: outputFile,
		ReportType: "auto",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	html, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}

	content := string(html)
	if !strings.Contains(content, "CloudGov Audit Report") {
		t.Error("missing audit report title")
	}
	if !strings.Contains(content, "2.5s") {
		t.Error("missing duration")
	}
}

func TestGenerate_Orphans(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "orphans.json")
	outputFile := filepath.Join(dir, "report.html")

	input := `{
		"resources": [
			{"Kind": "disk", "ID": "vol-123", "Name": "test", "Provider": "aws", "MonthlyCost": 10.50, "Detail": "100 GiB"}
		],
		"total": 1,
		"estimated_monthly_usd": 10.50
	}`
	if err := os.WriteFile(inputFile, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	err := Generate(Options{
		InputFile:  inputFile,
		OutputFile: outputFile,
		ReportType: "auto",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	html, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}

	content := string(html)
	if !strings.Contains(content, "10.50") {
		t.Error("missing cost value")
	}
}

func TestGenerate_MissingFile(t *testing.T) {
	err := Generate(Options{
		InputFile:  "/nonexistent/file.json",
		OutputFile: "/tmp/out.html",
	})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestGenerate_UnsupportedType(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(inputFile, []byte(`{"foo": "bar"}`), 0644); err != nil {
		t.Fatal(err)
	}

	err := Generate(Options{
		InputFile:  inputFile,
		OutputFile: filepath.Join(dir, "report.html"),
		ReportType: "auto",
	})
	if err == nil {
		t.Fatal("expected error for unsupported report type")
	}
}

func TestGenerate_Cost(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "cost.json")
	outputFile := filepath.Join(dir, "report.html")

	input := `{
		"diffs": [{
			"provider": "aws",
			"entries": [{"service": "EC2", "before": 100, "after": 120, "delta": 20, "pct_change": 20}],
			"total_before": 100,
			"total_after": 120,
			"total_delta": 20
		}]
	}`
	if err := os.WriteFile(inputFile, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	err := Generate(Options{
		InputFile:  inputFile,
		OutputFile: outputFile,
		ReportType: "auto",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	html, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(html), "Cost Report") {
		t.Error("missing cost report title")
	}
}

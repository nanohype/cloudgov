package compliance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadIAMReport(t *testing.T) {
	data := `{"findings":[{"severity":"CRITICAL","type":"ADMIN_ACCESS","provider":"aws","detail":"full admin"}],"total":1}`
	path := writeTemp(t, "iam.json", data)

	findings, err := LoadIAMReport(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Type != "ADMIN_ACCESS" {
		t.Errorf("got type %q, want ADMIN_ACCESS", findings[0].Type)
	}
}

func TestLoadStorageReport(t *testing.T) {
	data := `{"findings":[{"severity":"HIGH","type":"UNENCRYPTED","provider":"aws","bucket":"my-bucket"}],"total":1}`
	path := writeTemp(t, "storage.json", data)

	findings, err := LoadStorageReport(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Bucket != "my-bucket" {
		t.Errorf("got bucket %q, want my-bucket", findings[0].Bucket)
	}
}

func TestLoadNetworkReport(t *testing.T) {
	data := `{"findings":[{"severity":"CRITICAL","type":"ADMIN_PORT_OPEN","provider":"aws","resource":"sg-123"}],"total":1}`
	path := writeTemp(t, "network.json", data)

	findings, err := LoadNetworkReport(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Resource != "sg-123" {
		t.Errorf("got resource %q, want sg-123", findings[0].Resource)
	}
}

func TestLoadReportFileNotFound(t *testing.T) {
	_, err := LoadIAMReport("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadReportInvalidJSON(t *testing.T) {
	path := writeTemp(t, "bad.json", "not json")
	_, err := LoadIAMReport(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

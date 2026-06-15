package tags

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "resource-tagging.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

const validStandard = `{
  "kind": "nanohype/standards/resource-tagging",
  "content": {
    "required_by_surface": {
      "aws": ["Environment", "ManagedBy", "CostCenter"],
      "gcp": ["environment"]
    }
  }
}`

func TestLoadRequired(t *testing.T) {
	t.Run("valid returns aws keys", func(t *testing.T) {
		got, err := LoadRequired(writeTemp(t, validStandard))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"Environment", "ManagedBy", "CostCenter"}
		if len(got) != len(want) {
			t.Fatalf("got %v want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("key %d: got %q want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		if _, err := LoadRequired(filepath.Join(t.TempDir(), "nope.json")); err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("bad json errors", func(t *testing.T) {
		if _, err := LoadRequired(writeTemp(t, "{not json")); err == nil {
			t.Error("expected error for bad json")
		}
	})

	t.Run("wrong kind errors", func(t *testing.T) {
		body := `{"kind":"nanohype/standards/llm-policy","content":{"required_by_surface":{"aws":["Environment"]}}}`
		if _, err := LoadRequired(writeTemp(t, body)); err == nil {
			t.Error("expected error for wrong kind")
		}
	})

	t.Run("empty aws list errors", func(t *testing.T) {
		body := `{"kind":"nanohype/standards/resource-tagging","content":{"required_by_surface":{"gcp":["environment"]}}}`
		if _, err := LoadRequired(writeTemp(t, body)); err == nil {
			t.Error("expected error for empty aws list")
		}
	})
}

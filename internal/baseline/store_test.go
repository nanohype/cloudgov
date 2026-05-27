package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	report := json.RawMessage(`{"findings": [{"type": "test"}], "total": 1}`)

	if err := store.Save("scan-2024-01", report, "report.json"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Load("scan-2024-01")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got.Metadata.Name != "scan-2024-01" {
		t.Errorf("Name = %q, want %q", got.Metadata.Name, "scan-2024-01")
	}
	if got.Metadata.Source != "report.json" {
		t.Errorf("Source = %q, want %q", got.Metadata.Source, "report.json")
	}
	if got.Metadata.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}

	var roundTrip map[string]json.RawMessage
	if err := json.Unmarshal(got.Report, &roundTrip); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if _, ok := roundTrip["findings"]; !ok {
		t.Error("report missing 'findings' key")
	}
}

func TestOverwrite(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	report1 := json.RawMessage(`{"version": 1}`)
	report2 := json.RawMessage(`{"version": 2}`)

	if err := store.Save("scan", report1, "a.json"); err != nil {
		t.Fatalf("Save 1: %v", err)
	}
	if err := store.Save("scan", report2, "b.json"); err != nil {
		t.Fatalf("Save 2: %v", err)
	}

	got, err := store.Load("scan")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Metadata.Source != "b.json" {
		t.Errorf("Source = %q, want %q (overwrite failed)", got.Metadata.Source, "b.json")
	}

	var data map[string]int
	if err := json.Unmarshal(got.Report, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if data["version"] != 2 {
		t.Errorf("version = %d, want 2", data["version"])
	}
}

func TestListSortedByDate(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Save with small delays to ensure ordering
	for _, name := range []string{"alpha", "beta", "gamma"} {
		report := json.RawMessage(`{}`)
		if err := store.Save(name, report, ""); err != nil {
			t.Fatalf("Save %s: %v", name, err)
		}
		time.Sleep(10 * time.Millisecond) // ensure distinct timestamps
	}

	metas, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(metas) != 3 {
		t.Fatalf("got %d baselines, want 3", len(metas))
	}

	// Newest first
	if metas[0].Name != "gamma" {
		t.Errorf("first = %q, want gamma (newest)", metas[0].Name)
	}
	if metas[2].Name != "alpha" {
		t.Errorf("last = %q, want alpha (oldest)", metas[2].Name)
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	report := json.RawMessage(`{}`)
	if err := store.Save("to-delete", report, ""); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := store.Delete("to-delete"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := store.Load("to-delete")
	if err == nil {
		t.Fatal("expected error loading deleted baseline")
	}
}

func TestDeleteNotFound(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	err := store.Delete("nonexistent")
	if err == nil {
		t.Fatal("expected error deleting nonexistent baseline")
	}
}

func TestInvalidName(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	invalid := []string{"bad name", "bad/name", "bad.name", "../escape", ""}
	for _, name := range invalid {
		if err := store.Save(name, json.RawMessage(`{}`), ""); err == nil {
			t.Errorf("Save(%q): expected error for invalid name", name)
		}
		if _, err := store.Load(name); err == nil {
			t.Errorf("Load(%q): expected error for invalid name", name)
		}
		if err := store.Delete(name); err == nil {
			t.Errorf("Delete(%q): expected error for invalid name", name)
		}
	}
}

func TestInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := NewStore(dir)
	_, err := store.Load("bad")
	if err == nil {
		t.Fatal("expected error loading invalid JSON")
	}
}

func TestListEmptyDir(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	metas, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 0 {
		t.Errorf("got %d baselines, want 0", len(metas))
	}
}

func TestListNonexistentDir(t *testing.T) {
	store := NewStore("/tmp/cloudgov-test-nonexistent-" + t.Name())

	metas, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if metas != nil {
		t.Errorf("got %v, want nil", metas)
	}
}

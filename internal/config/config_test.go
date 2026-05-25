package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoConfigFile(t *testing.T) {
	// Run in a fresh temp dir so no .matlock.yaml is found
	tmp := t.TempDir()
	old, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(old) })
	_ = os.Chdir(tmp)
	// Also point HOME away from real home
	t.Setenv("HOME", tmp)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("missing config should be non-fatal, got: %v", err)
	}
	if cfg.DefaultDays != 90 {
		t.Errorf("default days: got %d, want 90", cfg.DefaultDays)
	}
	if len(cfg.DefaultProviders) != 0 {
		t.Errorf("default providers: got %v, want []", cfg.DefaultProviders)
	}
}

func TestLoad_FromYAMLFile(t *testing.T) {
	tmp := t.TempDir()
	old, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(old) })
	_ = os.Chdir(tmp)
	t.Setenv("HOME", tmp)

	yaml := `
providers: [aws, gcp]
days: 30
aws:
  region: us-west-2
  profile: dev
gcp:
  project: my-gcp-project
azure:
  subscription_id: sub-1234
`
	if err := os.WriteFile(filepath.Join(tmp, ".matlock.yaml"), []byte(yaml), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.DefaultProviders) != 2 || cfg.DefaultProviders[0] != "aws" {
		t.Errorf("providers: got %v", cfg.DefaultProviders)
	}
	if cfg.DefaultDays != 30 {
		t.Errorf("days: got %d, want 30", cfg.DefaultDays)
	}
	if cfg.AWS.Region != "us-west-2" || cfg.AWS.Profile != "dev" {
		t.Errorf("aws: got %+v", cfg.AWS)
	}
	if cfg.GCP.Project != "my-gcp-project" {
		t.Errorf("gcp: got %+v", cfg.GCP)
	}
	if cfg.Azure.SubscriptionID != "sub-1234" {
		t.Errorf("azure: got %+v", cfg.Azure)
	}
}

func TestLoad_MalformedYAMLReturnsError(t *testing.T) {
	tmp := t.TempDir()
	old, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(old) })
	_ = os.Chdir(tmp)
	t.Setenv("HOME", tmp)

	if err := os.WriteFile(filepath.Join(tmp, ".matlock.yaml"), []byte("not: valid: yaml: ["), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load()
	if err == nil {
		t.Fatal("expected error from malformed YAML")
	}
}

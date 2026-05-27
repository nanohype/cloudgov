package gcp

import (
	"context"
	"testing"

	"cloud.google.com/go/storage"
	"google.golang.org/api/compute/v1"
)

func TestAuditTags_NoRequired(t *testing.T) {
	p := &Provider{projectID: "p"}
	got, err := p.AuditTags(context.Background(), nil)
	if err != nil || got != nil {
		t.Errorf("expected (nil, nil), got (%v, %v)", got, err)
	}
}

func TestAuditTags_NoProject(t *testing.T) {
	p := &Provider{}
	_, err := p.AuditTags(context.Background(), []string{"owner"})
	if err == nil {
		t.Fatal("expected error for missing project")
	}
}

func TestAuditTags_InstanceMissingLabel(t *testing.T) {
	p := &Provider{
		projectID: "p",
		compute: &mockCompute{
			instances: map[string][]*compute.Instance{
				"zones/us-central1-a": {
					{Name: "vm-1", Zone: "zones/us-central1-a", Labels: map[string]string{"env": "prod"}},
				},
			},
		},
		newGCS: func(_ context.Context) (gcsAPI, error) { return &mockGCS{}, nil },
	}
	got, err := p.AuditTags(context.Background(), []string{"env", "owner"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "vm-1" || got[0].ResourceType != "compute:instance" {
		t.Errorf("expected one vm-1 finding, got %v", got)
	}
	if len(got[0].MissingTags) != 1 || got[0].MissingTags[0] != "owner" {
		t.Errorf("expected MissingTags=[owner], got %v", got[0].MissingTags)
	}
}

func TestAuditTags_BucketMissingLabel(t *testing.T) {
	p := &Provider{
		projectID: "p",
		compute:   &mockCompute{},
		newGCS: func(_ context.Context) (gcsAPI, error) {
			return &mockGCS{buckets: []*storage.BucketAttrs{
				{Name: "b1", Location: "US", Labels: map[string]string{"env": "prod"}},
			}}, nil
		},
	}
	got, _ := p.AuditTags(context.Background(), []string{"env", "owner"})
	if len(got) != 1 || got[0].ResourceID != "b1" || got[0].ResourceType != "gcs:bucket" {
		t.Errorf("expected one b1 finding, got %v", got)
	}
}

func TestGCPMissingLabels(t *testing.T) {
	have := map[string]struct{}{"env": {}}
	got := gcpMissingLabels([]string{"env", "owner"}, have)
	if len(got) != 1 || got[0] != "owner" {
		t.Errorf("got %v", got)
	}
	got = gcpMissingLabels([]string{"env"}, have)
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestLastSlash(t *testing.T) {
	tests := []struct {
		s    string
		want int
	}{
		{"a/b/c", 3},
		{"abc", -1},
		{"/", 0},
	}
	for _, tt := range tests {
		got := lastSlash(tt.s)
		if got != tt.want {
			t.Errorf("lastSlash(%q): got %d, want %d", tt.s, got, tt.want)
		}
	}
}

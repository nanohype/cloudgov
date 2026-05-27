package gcp

import (
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/storage"

	"github.com/stxkxs/matlock/internal/cloud"
)

type mockGCS struct {
	buckets []*storage.BucketAttrs
	err     error
	closed  bool
}

func (m *mockGCS) ListBuckets(_ context.Context, _ string) ([]*storage.BucketAttrs, error) {
	return m.buckets, m.err
}
func (m *mockGCS) Close() error { m.closed = true; return nil }

func newStorageProvider(g *mockGCS) *Provider {
	return &Provider{
		projectID: "p",
		newGCS:    func(_ context.Context) (gcsAPI, error) { return g, nil },
	}
}

func TestAuditStorage_NoBuckets(t *testing.T) {
	p := newStorageProvider(&mockGCS{})
	got, err := p.AuditStorage(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no findings, got %v", got)
	}
}

func TestAuditStorage_PublicBucketIsCritical(t *testing.T) {
	p := newStorageProvider(&mockGCS{buckets: []*storage.BucketAttrs{
		{Name: "public", Location: "us-central1",
			ACL:               []storage.ACLRule{{Entity: storage.AllUsers}},
			Logging:           &storage.BucketLogging{LogBucket: "logs"},
			VersioningEnabled: true,
		},
	}})
	got, err := p.AuditStorage(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Severity != cloud.SeverityCritical || got[0].Type != cloud.BucketPublicAccess {
		t.Errorf("expected one critical public-access finding, got %v", got)
	}
}

func TestAuditStorage_PublicAccessPreventionSkipsACLCheck(t *testing.T) {
	p := newStorageProvider(&mockGCS{buckets: []*storage.BucketAttrs{
		{Name: "safe", PublicAccessPrevention: storage.PublicAccessPreventionEnforced,
			ACL:     []storage.ACLRule{{Entity: storage.AllUsers}}, // would normally be public
			Logging: &storage.BucketLogging{LogBucket: "logs"}, VersioningEnabled: true,
		},
	}})
	got, _ := p.AuditStorage(context.Background())
	if len(got) != 0 {
		t.Errorf("PAP=Enforced should suppress public-access finding, got %v", got)
	}
}

func TestAuditStorage_NoVersioning(t *testing.T) {
	p := newStorageProvider(&mockGCS{buckets: []*storage.BucketAttrs{
		{Name: "no-version", Logging: &storage.BucketLogging{LogBucket: "logs"}},
	}})
	got, _ := p.AuditStorage(context.Background())
	if len(got) != 1 || got[0].Type != cloud.BucketNoVersioning {
		t.Errorf("expected one no-versioning finding, got %v", got)
	}
}

func TestAuditStorage_NoLogging(t *testing.T) {
	p := newStorageProvider(&mockGCS{buckets: []*storage.BucketAttrs{
		{Name: "no-logs", VersioningEnabled: true},
	}})
	got, _ := p.AuditStorage(context.Background())
	if len(got) != 1 || got[0].Type != cloud.BucketNoLogging {
		t.Errorf("expected one no-logging finding, got %v", got)
	}
}

func TestAuditStorage_ClientCloses(t *testing.T) {
	mock := &mockGCS{}
	p := newStorageProvider(mock)
	_, _ = p.AuditStorage(context.Background())
	if !mock.closed {
		t.Error("expected GCS client to be closed")
	}
}

func TestAuditStorage_FactoryError(t *testing.T) {
	p := &Provider{
		projectID: "p",
		newGCS:    func(_ context.Context) (gcsAPI, error) { return nil, errors.New("auth") },
	}
	_, err := p.AuditStorage(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

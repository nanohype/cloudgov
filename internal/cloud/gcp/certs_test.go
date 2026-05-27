package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/api/certificatemanager/v1"
)

type mockCertManager struct {
	certs []*certificatemanager.Certificate
	err   error
}

func (m *mockCertManager) ListCertificates(_ context.Context, _ string) ([]*certificatemanager.Certificate, error) {
	return m.certs, m.err
}

func TestListCertificates(t *testing.T) {
	now := time.Now()
	soon := now.Add(7 * 24 * time.Hour).Format(time.RFC3339)
	later := now.Add(60 * 24 * time.Hour).Format(time.RFC3339)
	farFuture := now.Add(365 * 24 * time.Hour).Format(time.RFC3339)

	p := &Provider{projectID: "p", certManager: &mockCertManager{certs: []*certificatemanager.Certificate{
		{Name: "projects/p/locations/us/certificates/soon", ExpireTime: soon},
		{Name: "projects/p/locations/us/certificates/later", ExpireTime: later},
		{Name: "projects/p/locations/us/certificates/future", ExpireTime: farFuture},
		{Name: "projects/p/locations/us/certificates/no-expiry"}, // skipped
	}}}
	got, err := p.ListCertificates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 findings (within 180-day window), got %d: %v", len(got), got)
	}
}

func TestListCertificates_NoProject(t *testing.T) {
	p := &Provider{certManager: &mockCertManager{}}
	_, err := p.ListCertificates(context.Background())
	if err == nil {
		t.Fatal("expected error for missing project")
	}
}

func TestListCertificates_APINotEnabledReturnsEmpty(t *testing.T) {
	p := &Provider{projectID: "p", certManager: &mockCertManager{err: errors.New("API not enabled")}}
	got, err := p.ListCertificates(context.Background())
	if err != nil {
		t.Errorf("expected nil error when API disabled (warn-and-return-empty), got: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil findings, got %v", got)
	}
}

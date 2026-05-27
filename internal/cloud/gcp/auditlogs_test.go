package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"cloud.google.com/go/logging"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/stxkxs/matlock/internal/cloud"
)

type mockLogAdmin struct {
	entries []*logging.Entry
	err     error
	closed  bool
}

func (m *mockLogAdmin) Entries(_ context.Context, _ string) ([]*logging.Entry, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.entries, nil
}

func (m *mockLogAdmin) Close() error { m.closed = true; return nil }

func TestAuditLogPermissions(t *testing.T) {
	t1 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC)

	entries := []*logging.Entry{
		{Timestamp: t1, Payload: map[string]interface{}{"methodName": "storage.objects.get"}},
		{Timestamp: t2, Payload: map[string]interface{}{"methodName": "storage.objects.get"}}, // duplicate; latest ts wins
		{Timestamp: t1, Payload: map[string]interface{}{"methodName": "compute.instances.list"}},
		{Timestamp: t1, Payload: map[string]interface{}{}}, // no methodName, skipped
	}

	mock := &mockLogAdmin{entries: entries}
	p := &Provider{
		projectID: "my-project",
		newLogAdmin: func(_ context.Context, _ string) (logAdminAPI, error) {
			return mock, nil
		},
	}

	got, err := p.auditLogPermissions(context.Background(),
		cloud.Principal{Name: "alice@example.com", Type: cloud.PrincipalUser},
		t1.Add(-24*time.Hour),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 unique permissions, got %d: %v", len(got), got)
	}
	if !mock.closed {
		t.Error("expected logadmin client to be closed")
	}
	// Every returned permission should have a LastUsed timestamp.
	for _, perm := range got {
		if perm.LastUsed == nil {
			t.Errorf("permission %s missing LastUsed", perm.Action)
		}
		if perm.Resource != "projects/my-project" {
			t.Errorf("resource: got %q", perm.Resource)
		}
	}
}

func TestAuditLogPermissions_FactoryError(t *testing.T) {
	p := &Provider{
		projectID: "p",
		newLogAdmin: func(_ context.Context, _ string) (logAdminAPI, error) {
			return nil, errors.New("auth")
		},
	}
	_, err := p.auditLogPermissions(context.Background(), cloud.Principal{Name: "a"}, time.Now())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuditLogPermissions_EntriesError(t *testing.T) {
	p := &Provider{
		projectID: "p",
		newLogAdmin: func(_ context.Context, _ string) (logAdminAPI, error) {
			return &mockLogAdmin{err: errors.New("throttled")}, nil
		},
	}
	_, err := p.auditLogPermissions(context.Background(), cloud.Principal{Name: "a"}, time.Now())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExtractMethod(t *testing.T) {
	tests := []struct {
		name    string
		payload interface{}
		want    string
	}{
		{"nil payload", nil, ""},
		{"map with methodName", map[string]interface{}{"methodName": "storage.objects.get"}, "storage.objects.get"},
		{"map without methodName", map[string]interface{}{"other": "value"}, ""},
		{"structpb with methodName", &structpb.Struct{Fields: map[string]*structpb.Value{
			"methodName": structpb.NewStringValue("compute.instances.list"),
		}}, "compute.instances.list"},
		{"structpb without methodName", &structpb.Struct{Fields: map[string]*structpb.Value{}}, ""},
		{"unrelated type", "string-payload", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMethod(tt.payload)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

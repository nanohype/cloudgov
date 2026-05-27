package azure

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"

	"github.com/stxkxs/matlock/internal/cloud"
)

type mockActivityLogs struct {
	events []*armmonitor.EventData
	err    error
}

func (m *mockActivityLogs) List(_ context.Context, _ string) ([]*armmonitor.EventData, error) {
	return m.events, m.err
}

func TestActivityLogPermissions(t *testing.T) {
	t1 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC)
	p := &Provider{activityLogs: &mockActivityLogs{events: []*armmonitor.EventData{
		{
			OperationName:  &armmonitor.LocalizableString{Value: to.Ptr("Microsoft.Storage/storageAccounts/read")},
			ResourceID:     to.Ptr("/subscriptions/s/resources/foo"),
			EventTimestamp: &t1,
		},
		{
			OperationName:  &armmonitor.LocalizableString{Value: to.Ptr("Microsoft.Storage/storageAccounts/read")},
			ResourceID:     to.Ptr("/subscriptions/s/resources/foo"),
			EventTimestamp: &t2, // duplicate; later ts wins
		},
		{
			OperationName: nil, // skipped
		},
	}}}
	got, err := p.activityLogPermissions(context.Background(),
		cloud.Principal{Name: "alice@example.com"}, t1.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 perm (dedup), got %d: %v", len(got), got)
	}
	if got[0].Action != "Microsoft.Storage/storageAccounts/read" {
		t.Errorf("action: got %q", got[0].Action)
	}
}

func TestActivityLogPermissions_Error(t *testing.T) {
	p := &Provider{activityLogs: &mockActivityLogs{err: errors.New("auth")}}
	_, err := p.activityLogPermissions(context.Background(), cloud.Principal{Name: "x"}, time.Now())
	if err == nil {
		t.Fatal("expected error")
	}
}

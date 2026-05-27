package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/stxkxs/matlock/internal/cloud"
)

// activityLogsAPI is the narrow Activity Logs surface used by this package.
type activityLogsAPI interface {
	List(ctx context.Context, filter string) ([]*armmonitor.EventData, error)
}

type activityLogsAdapter struct {
	client *armmonitor.ActivityLogsClient
}

func (a *activityLogsAdapter) List(ctx context.Context, filter string) ([]*armmonitor.EventData, error) {
	var out []*armmonitor.EventData
	pager := a.client.NewListPager(filter, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

// activityLogPermissions queries the Azure Activity Log for operations performed by the principal.
func (p *Provider) activityLogPermissions(ctx context.Context, principal cloud.Principal, since time.Time) ([]cloud.Permission, error) {
	filter := fmt.Sprintf(
		"eventTimestamp ge '%s' and caller eq '%s'",
		since.UTC().Format(time.RFC3339),
		principal.Name,
	)

	events, err := p.activityLogs.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("list activity logs: %w", err)
	}

	seen := make(map[string]time.Time)
	for _, event := range events {
		if event.OperationName == nil || event.OperationName.Value == nil {
			continue
		}
		op := *event.OperationName.Value
		scope := ""
		if event.ResourceID != nil {
			scope = *event.ResourceID
		}
		key := op + "|" + scope
		ts := time.Now()
		if event.EventTimestamp != nil {
			ts = *event.EventTimestamp
		}
		if prev, ok := seen[key]; !ok || ts.After(prev) {
			seen[key] = ts
		}
	}

	perms := make([]cloud.Permission, 0, len(seen))
	for key, ts := range seen {
		parts := strings.SplitN(key, "|", 2)
		action, resource := parts[0], ""
		if len(parts) == 2 {
			resource = parts[1]
		}
		t := ts
		ts8601 := t.UTC().Format(time.RFC3339)
		perms = append(perms, cloud.Permission{
			Action:   action,
			Resource: resource,
			LastUsed: &ts8601,
		})
	}
	return perms, nil
}

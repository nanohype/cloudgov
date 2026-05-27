package aws

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/stxkxs/matlock/internal/cloud"
)

// cloudtrailAPI is the narrow CloudTrail surface used by this package.
type cloudtrailAPI interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// cloudtrailUsedPermissions queries CloudTrail for events attributed to principal
// between since and now, returning the unique set of service:Action pairs used.
func (p *Provider) cloudtrailUsedPermissions(ctx context.Context, principal cloud.Principal, since time.Time) ([]cloud.Permission, error) {
	// Build lookup attributes: filter by username or ARN
	attrs := []cttypes.LookupAttribute{}
	if arn, ok := principal.Metadata["arn"]; ok && arn != "" {
		attrs = append(attrs, cttypes.LookupAttribute{
			AttributeKey:   cttypes.LookupAttributeKeyResourceName,
			AttributeValue: awssdk.String(arn),
		})
	} else {
		attrs = append(attrs, cttypes.LookupAttribute{
			AttributeKey:   cttypes.LookupAttributeKeyUsername,
			AttributeValue: awssdk.String(principal.Name),
		})
	}

	now := time.Now()
	seen := make(map[string]time.Time) // action|resource → last used

	pager := cloudtrail.NewLookupEventsPaginator(p.cloudtrail, &cloudtrail.LookupEventsInput{
		LookupAttributes: attrs,
		StartTime:        awssdk.Time(since),
		EndTime:          awssdk.Time(now),
		MaxResults:       awssdk.Int32(50),
	})

	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: cloudtrail lookup page: %v\n", err)
			break
		}
		for _, event := range page.Events {
			if event.EventSource == nil || event.EventName == nil {
				continue
			}
			action := normalizeAction(awssdk.ToString(event.EventSource), awssdk.ToString(event.EventName))
			resource := extractResource(event)
			key := action + "|" + resource

			ts := now
			if event.EventTime != nil {
				ts = *event.EventTime
			}
			if prev, ok := seen[key]; !ok || ts.After(prev) {
				seen[key] = ts
			}
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

// normalizeAction converts "s3.amazonaws.com" + "GetObject" → "s3:GetObject".
func normalizeAction(eventSource, eventName string) string {
	svc := strings.TrimSuffix(eventSource, ".amazonaws.com")
	// Drop subdomain prefix (e.g. "bucket.s3" → "s3")
	if i := strings.LastIndex(svc, "."); i >= 0 {
		svc = svc[i+1:]
	}
	return svc + ":" + eventName
}

// extractResource pulls the first resource ARN from a CloudTrail event.
func extractResource(event cttypes.Event) string {
	for _, r := range event.Resources {
		if r.ResourceName != nil {
			return awssdk.ToString(r.ResourceName)
		}
	}
	return "*"
}

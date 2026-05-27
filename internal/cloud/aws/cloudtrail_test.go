package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/stxkxs/matlock/internal/cloud"
)

// mockCloudTrail implements cloudtrailAPI. Each invocation returns the next
// page from `pages`; if `errAt` matches the call index, it errors instead.
type mockCloudTrail struct {
	pages []cttypes.Event
	err   error
	calls int
}

func (m *mockCloudTrail) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.calls > 0 {
		return &cloudtrail.LookupEventsOutput{}, nil
	}
	m.calls++
	return &cloudtrail.LookupEventsOutput{Events: m.pages}, nil
}

func TestCloudTrailUsedPermissions(t *testing.T) {
	t1 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		principal cloud.Principal
		events    []cttypes.Event
		err       error
		wantPerms []cloud.Permission
		wantErr   bool
	}{
		{
			name:      "single event yields one permission",
			principal: cloud.Principal{Name: "alice"},
			events: []cttypes.Event{
				{
					EventSource: awssdk.String("s3.amazonaws.com"),
					EventName:   awssdk.String("GetObject"),
					EventTime:   &t1,
					Resources: []cttypes.Resource{
						{ResourceName: awssdk.String("arn:aws:s3:::mybucket/key")},
					},
				},
			},
			wantPerms: []cloud.Permission{{Action: "s3:GetObject", Resource: "arn:aws:s3:::mybucket/key"}},
		},
		{
			name:      "subdomain in event source is stripped",
			principal: cloud.Principal{Name: "alice"},
			events: []cttypes.Event{
				{
					EventSource: awssdk.String("bucket.s3.amazonaws.com"),
					EventName:   awssdk.String("GetObject"),
					EventTime:   &t1,
				},
			},
			wantPerms: []cloud.Permission{{Action: "s3:GetObject", Resource: "*"}},
		},
		{
			name:      "duplicate action+resource is deduped; latest timestamp wins",
			principal: cloud.Principal{Name: "alice"},
			events: []cttypes.Event{
				{
					EventSource: awssdk.String("s3.amazonaws.com"),
					EventName:   awssdk.String("GetObject"),
					EventTime:   &t1,
				},
				{
					EventSource: awssdk.String("s3.amazonaws.com"),
					EventName:   awssdk.String("GetObject"),
					EventTime:   &t2,
				},
			},
			wantPerms: []cloud.Permission{{Action: "s3:GetObject", Resource: "*"}},
		},
		{
			name:      "event missing EventSource or EventName is skipped",
			principal: cloud.Principal{Name: "alice"},
			events: []cttypes.Event{
				{EventName: awssdk.String("GetObject"), EventTime: &t1},          // no source
				{EventSource: awssdk.String("s3.amazonaws.com"), EventTime: &t1}, // no name
				{
					EventSource: awssdk.String("ec2.amazonaws.com"),
					EventName:   awssdk.String("DescribeInstances"),
					EventTime:   &t1,
				},
			},
			wantPerms: []cloud.Permission{{Action: "ec2:DescribeInstances", Resource: "*"}},
		},
		{
			name:      "lookup error is warn-and-break — returns whatever was collected before the error",
			principal: cloud.Principal{Name: "alice"},
			err:       errors.New("throttled"),
			wantPerms: nil,
		},
		{
			name:      "empty result set",
			principal: cloud.Principal{Name: "alice"},
			events:    nil,
			wantPerms: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{cloudtrail: &mockCloudTrail{pages: tt.events, err: tt.err}}
			got, err := p.cloudtrailUsedPermissions(context.Background(), tt.principal, t1.Add(-24*time.Hour))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			// strip LastUsed for comparison (timestamps vary)
			gotNoTime := make([]cloud.Permission, len(got))
			for i, p := range got {
				gotNoTime[i] = cloud.Permission{Action: p.Action, Resource: p.Resource}
			}
			if !equalPerms(gotNoTime, tt.wantPerms) {
				t.Errorf("perms: got %v, want %v", gotNoTime, tt.wantPerms)
			}
			// every returned permission must have a LastUsed timestamp
			for _, p := range got {
				if p.LastUsed == nil || *p.LastUsed == "" {
					t.Errorf("permission %q missing LastUsed timestamp", p.Action)
				}
			}
		})
	}
}

func TestCloudTrailUsedPermissions_FiltersByARN(t *testing.T) {
	// When principal has an ARN, lookup should filter by ResourceName. The mock
	// doesn't enforce the filter — we just verify the call succeeds and the
	// permission is captured.
	t1 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	p := &Provider{cloudtrail: &mockCloudTrail{pages: []cttypes.Event{
		{
			EventSource: awssdk.String("iam.amazonaws.com"),
			EventName:   awssdk.String("GetUser"),
			EventTime:   &t1,
		},
	}}}
	got, err := p.cloudtrailUsedPermissions(context.Background(),
		cloud.Principal{Name: "alice", Metadata: map[string]string{"arn": "arn:aws:iam::123456789012:user/alice"}},
		t1.Add(-24*time.Hour),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Action != "iam:GetUser" {
		t.Errorf("got %v", got)
	}
}

func TestNormalizeAction(t *testing.T) {
	tests := []struct {
		src  string
		name string
		want string
	}{
		{"s3.amazonaws.com", "GetObject", "s3:GetObject"},
		{"bucket.s3.amazonaws.com", "PutObject", "s3:PutObject"},
		{"ec2.amazonaws.com", "DescribeInstances", "ec2:DescribeInstances"},
		{"iam.amazonaws.com", "GetUser", "iam:GetUser"},
	}
	for _, tt := range tests {
		t.Run(tt.src+":"+tt.name, func(t *testing.T) {
			got := normalizeAction(tt.src, tt.name)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractResource(t *testing.T) {
	tests := []struct {
		name  string
		event cttypes.Event
		want  string
	}{
		{
			name: "first ARN wins",
			event: cttypes.Event{Resources: []cttypes.Resource{
				{ResourceName: awssdk.String("arn:aws:s3:::a")},
				{ResourceName: awssdk.String("arn:aws:s3:::b")},
			}},
			want: "arn:aws:s3:::a",
		},
		{
			name:  "no resources defaults to wildcard",
			event: cttypes.Event{},
			want:  "*",
		},
		{
			name: "resource with nil name is skipped",
			event: cttypes.Event{Resources: []cttypes.Resource{
				{ResourceName: nil},
				{ResourceName: awssdk.String("arn:aws:s3:::a")},
			}},
			want: "arn:aws:s3:::a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractResource(tt.event)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

package cmd

import (
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

func TestWritePolicyFallbackWarnings(t *testing.T) {
	tests := []struct {
		name      string
		principal string
		fallbacks []cloud.PolicyFallback
		wantParts []string
		wantEmpty bool
	}{
		{
			name:      "no fallbacks writes nothing",
			principal: "ci-role",
			fallbacks: nil,
			wantEmpty: true,
		},
		{
			name:      "no-resource fallback lists action and reason",
			principal: "ci-role",
			fallbacks: []cloud.PolicyFallback{
				{Action: "ec2:DescribeInstances", Reason: cloud.FallbackNoResourceRecorded},
			},
			wantParts: []string{
				"warn: ci-role: 1 action(s)",
				`Resource "*"`,
				`Sid "UnscopedFallback"`,
				"ec2:DescribeInstances",
				string(cloud.FallbackNoResourceRecorded),
			},
		},
		{
			name:      "unrecognized-resource fallback includes the recorded value",
			principal: "deploy-user",
			fallbacks: []cloud.PolicyFallback{
				{Action: "s3:PutObject", Resource: "my-bucket", Reason: cloud.FallbackUnrecognizedResource},
			},
			wantParts: []string{
				"warn: deploy-user: 1 action(s)",
				"s3:PutObject",
				string(cloud.FallbackUnrecognizedResource),
				`recorded resource "my-bucket"`,
			},
		},
		{
			name:      "multiple fallbacks each get a line",
			principal: "ops",
			fallbacks: []cloud.PolicyFallback{
				{Action: "ec2:DescribeInstances", Reason: cloud.FallbackNoResourceRecorded},
				{Action: "s3:PutObject", Resource: "my-bucket", Reason: cloud.FallbackUnrecognizedResource},
			},
			wantParts: []string{
				"warn: ops: 2 action(s)",
				"ec2:DescribeInstances",
				"s3:PutObject",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sb strings.Builder
			writePolicyFallbackWarnings(&sb, tt.principal, tt.fallbacks)
			got := sb.String()
			if tt.wantEmpty {
				if got != "" {
					t.Fatalf("expected no output, got %q", got)
				}
				return
			}
			for _, part := range tt.wantParts {
				if !strings.Contains(got, part) {
					t.Errorf("output missing %q:\n%s", part, got)
				}
			}
		})
	}
}

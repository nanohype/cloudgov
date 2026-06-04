package aws

import (
	"context"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/nanohype/cloudgov/internal/cloud"
)

type mockEKS struct{ clusters []string }

func (m mockEKS) ListClusters(_ context.Context, _ *eks.ListClustersInput, _ ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	return &eks.ListClustersOutput{Clusters: m.clusters}, nil
}

type mockLogs struct{ groups []string }

func (m mockLogs) DescribeLogGroups(_ context.Context, _ *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	var lgs []cwltypes.LogGroup
	for _, g := range m.groups {
		lgs = append(lgs, cwltypes.LogGroup{LogGroupName: awssdk.String(g)})
	}
	return &cloudwatchlogs.DescribeLogGroupsOutput{LogGroups: lgs}, nil
}

type mockSQS struct{ urls []string }

func (m mockSQS) ListQueues(_ context.Context, _ *sqs.ListQueuesInput, _ ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	return &sqs.ListQueuesOutput{QueueUrls: m.urls}, nil
}

type ebRule struct {
	arn, name, clusterTag string
	tagged                bool
}

type mockEventBridge struct{ rules []ebRule }

func (m mockEventBridge) ListRules(_ context.Context, _ *eventbridge.ListRulesInput, _ ...func(*eventbridge.Options)) (*eventbridge.ListRulesOutput, error) {
	var rs []ebtypes.Rule
	for _, r := range m.rules {
		rs = append(rs, ebtypes.Rule{Arn: awssdk.String(r.arn), Name: awssdk.String(r.name)})
	}
	return &eventbridge.ListRulesOutput{Rules: rs}, nil
}

func (m mockEventBridge) ListTagsForResource(_ context.Context, in *eventbridge.ListTagsForResourceInput, _ ...func(*eventbridge.Options)) (*eventbridge.ListTagsForResourceOutput, error) {
	for _, r := range m.rules {
		if r.arn == awssdk.ToString(in.ResourceARN) && r.tagged {
			return &eventbridge.ListTagsForResourceOutput{Tags: []ebtypes.Tag{
				{Key: awssdk.String("ClusterName"), Value: awssdk.String(r.clusterTag)},
			}}, nil
		}
	}
	return &eventbridge.ListTagsForResourceOutput{}, nil
}

func TestOrphanClusterResidue(t *testing.T) {
	p := &Provider{
		eks: mockEKS{clusters: []string{"live"}},
		logs: mockLogs{groups: []string{
			"/aws/eks/live/cluster", // live → skip
			"/aws/eks/dead/cluster", // dead → orphan
			"/aws/lambda/whatever",  // not an EKS log group → skip
		}},
		sqs: mockSQS{urls: []string{
			"https://sqs.us-west-2.amazonaws.com/111/Karpenter-live", // live → skip
			"https://sqs.us-west-2.amazonaws.com/111/Karpenter-dead", // dead → orphan
		}},
		eventbridge: mockEventBridge{rules: []ebRule{
			{arn: "arn:aws:events:us-west-2:111:rule/KarpenterSpot-1", name: "KarpenterSpot-1", clusterTag: "live", tagged: true}, // live → skip
			{arn: "arn:aws:events:us-west-2:111:rule/KarpenterSpot-2", name: "KarpenterSpot-2", clusterTag: "dead", tagged: true}, // dead → orphan
			{arn: "arn:aws:events:us-west-2:111:rule/KarpenterSpot-3", name: "KarpenterSpot-3", tagged: false},                     // untagged → debris orphan
		}},
	}

	got := p.orphanClusterResidue(context.Background())

	byKind := map[cloud.OrphanKind]int{}
	for _, o := range got {
		byKind[o.Kind]++
		if !o.Kind.AlwaysReport() {
			t.Errorf("cluster-residue kind %q should be AlwaysReport", o.Kind)
		}
		if strings.Contains(o.Name, "live") || strings.Contains(o.Detail, "\"live\"") {
			t.Errorf("a LIVE cluster's residue was flagged: %+v", o)
		}
	}
	if byKind[cloud.OrphanEKSLogGroup] != 1 {
		t.Errorf("log groups: got %d, want 1 (the dead cluster's)", byKind[cloud.OrphanEKSLogGroup])
	}
	if byKind[cloud.OrphanKarpenterQueue] != 1 {
		t.Errorf("karpenter queues: got %d, want 1", byKind[cloud.OrphanKarpenterQueue])
	}
	if byKind[cloud.OrphanKarpenterRule] != 2 {
		t.Errorf("karpenter rules: got %d, want 2 (dead + untagged debris)", byKind[cloud.OrphanKarpenterRule])
	}
}

func TestEKSClusterFromLogGroup(t *testing.T) {
	cases := map[string]string{
		"/aws/eks/dev-eks/cluster":  "dev-eks",
		"/aws/eks/a/b/c/cluster":    "a/b/c",
		"/aws/lambda/foo":           "",
		"/aws/eks//cluster":         "",
		"/aws/eks/x/something-else": "",
	}
	for in, want := range cases {
		if got := eksClusterFromLogGroup(in); got != want {
			t.Errorf("eksClusterFromLogGroup(%q) = %q, want %q", in, got, want)
		}
	}
}

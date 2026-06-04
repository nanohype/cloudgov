package aws

import (
	"context"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/nanohype/cloudgov/internal/cloud"
)

// Narrow surfaces for cluster-residue detection. The concrete SDK clients satisfy
// these; tests pass hand-written mocks. (Each first-used here, per the package rule.)
type eksAPI interface {
	ListClusters(ctx context.Context, params *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	DescribeCluster(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
}

type logsAPI interface {
	DescribeLogGroups(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
}

type sqsAPI interface {
	ListQueues(ctx context.Context, params *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error)
	ListQueueTags(ctx context.Context, params *sqs.ListQueueTagsInput, optFns ...func(*sqs.Options)) (*sqs.ListQueueTagsOutput, error)
}

type eventBridgeAPI interface {
	ListRules(ctx context.Context, params *eventbridge.ListRulesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListRulesOutput, error)
	ListTagsForResource(ctx context.Context, params *eventbridge.ListTagsForResourceInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListTagsForResourceOutput, error)
}

// orphanClusterResidue finds resources tied to a now-deleted EKS cluster that the
// cluster's IaC teardown can't reach: the control-plane log group (which blocks a
// same-named re-vend with ResourceAlreadyExistsException) and Karpenter's
// interruption infra (the SQS queue + EventBridge rules). Each candidate is matched
// against the LIVE cluster set (eks:ListClusters); only residue whose owning cluster
// is gone is reported, so a live cluster's resources are never flagged. A Karpenter
// rule missing the ClusterName tag is failed-create debris (a healthy rule from the
// module always carries it). If liveness can't be determined, the scan is skipped
// to avoid false positives.
func (p *Provider) orphanClusterResidue(ctx context.Context) []cloud.OrphanResource {
	if p.eks == nil {
		return nil // residue detection needs the EKS client for the liveness check
	}
	live, err := p.liveEKSClusters(ctx)
	if err != nil {
		p.warnf("warn: list eks clusters (skipping cluster-residue scan): %v\n", err)
		return nil
	}
	var out []cloud.OrphanResource
	out = append(out, p.orphanEKSLogGroups(ctx, live)...)
	out = append(out, p.orphanKarpenterQueues(ctx, live)...)
	out = append(out, p.orphanKarpenterRules(ctx, live)...)
	return out
}

func (p *Provider) liveEKSClusters(ctx context.Context) (map[string]bool, error) {
	live := map[string]bool{}
	var token *string
	for {
		out, err := p.eks.ListClusters(ctx, &eks.ListClustersInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		for _, name := range out.Clusters {
			live[name] = true
		}
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}
	return live, nil
}

func (p *Provider) orphanEKSLogGroups(ctx context.Context, live map[string]bool) []cloud.OrphanResource {
	if p.logs == nil {
		return nil
	}
	var out []cloud.OrphanResource
	var token *string
	for {
		page, err := p.logs.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
			LogGroupNamePrefix: awssdk.String("/aws/eks/"),
			NextToken:          token,
		})
		if err != nil {
			p.warnf("warn: describe log groups page: %v\n", err)
			break
		}
		for _, lg := range page.LogGroups {
			name := awssdk.ToString(lg.LogGroupName)
			cluster := eksClusterFromLogGroup(name)
			if cluster == "" || live[cluster] {
				continue
			}
			out = append(out, cloud.OrphanResource{
				Kind:     cloud.OrphanEKSLogGroup,
				ID:       name,
				Name:     name,
				Region:   p.cfg.Region,
				Provider: "aws",
				Detail:   fmt.Sprintf("EKS control-plane log group for deleted cluster %q; blocks a same-named re-vend", cluster),
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return out
}

// eksClusterFromLogGroup extracts <cluster> from /aws/eks/<cluster>/cluster, or ""
// if the name doesn't match that shape.
func eksClusterFromLogGroup(name string) string {
	const prefix, suffix = "/aws/eks/", "/cluster"
	if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) && len(name) > len(prefix)+len(suffix) {
		return name[len(prefix) : len(name)-len(suffix)]
	}
	return ""
}

func (p *Provider) orphanKarpenterQueues(ctx context.Context, live map[string]bool) []cloud.OrphanResource {
	if p.sqs == nil {
		return nil
	}
	var out []cloud.OrphanResource
	var token *string
	for {
		page, err := p.sqs.ListQueues(ctx, &sqs.ListQueuesInput{
			QueueNamePrefix: awssdk.String("Karpenter-"),
			NextToken:       token,
		})
		if err != nil {
			p.warnf("warn: list queues page: %v\n", err)
			break
		}
		for _, url := range page.QueueUrls {
			name := url[strings.LastIndex(url, "/")+1:]
			cluster := strings.TrimPrefix(name, "Karpenter-")
			if cluster == name || cluster == "" || live[cluster] {
				continue
			}
			out = append(out, cloud.OrphanResource{
				Kind:     cloud.OrphanKarpenterQueue,
				ID:       url,
				Name:     name,
				Region:   p.cfg.Region,
				Provider: "aws",
				Detail:   fmt.Sprintf("Karpenter interruption queue for deleted cluster %q", cluster),
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return out
}

func (p *Provider) orphanKarpenterRules(ctx context.Context, live map[string]bool) []cloud.OrphanResource {
	if p.eventbridge == nil {
		return nil
	}
	var out []cloud.OrphanResource
	var token *string
	for {
		page, err := p.eventbridge.ListRules(ctx, &eventbridge.ListRulesInput{
			NamePrefix: awssdk.String("Karpenter"),
			NextToken:  token,
		})
		if err != nil {
			p.warnf("warn: list eventbridge rules: %v\n", err)
			break
		}
		for _, r := range page.Rules {
			cluster, tagged := p.ruleClusterName(ctx, awssdk.ToString(r.Arn))
			if tagged && live[cluster] {
				continue // healthy rule for a live cluster
			}
			detail := fmt.Sprintf("Karpenter interruption rule for deleted cluster %q", cluster)
			if !tagged {
				detail = "Karpenter interruption rule with no ClusterName tag (failed-create debris)"
			}
			out = append(out, cloud.OrphanResource{
				Kind:     cloud.OrphanKarpenterRule,
				ID:       awssdk.ToString(r.Arn),
				Name:     awssdk.ToString(r.Name),
				Region:   p.cfg.Region,
				Provider: "aws",
				Detail:   detail,
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	return out
}

// ruleClusterName returns an EventBridge rule's ClusterName tag value and whether
// it was present.
func (p *Provider) ruleClusterName(ctx context.Context, arn string) (string, bool) {
	out, err := p.eventbridge.ListTagsForResource(ctx, &eventbridge.ListTagsForResourceInput{
		ResourceARN: awssdk.String(arn),
	})
	if err != nil {
		return "", false
	}
	for _, t := range out.Tags {
		if awssdk.ToString(t.Key) == "ClusterName" {
			return awssdk.ToString(t.Value), true
		}
	}
	return "", false
}

package aws

import (
	"context"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
)

// ── ECS ──────────────────────────────────────────────────────────────────────

type tagsMockECS struct {
	arns []string
	tags map[string]map[string]string // cluster ARN -> tags
}

func (m *tagsMockECS) ListClusters(_ context.Context, _ *ecs.ListClustersInput, _ ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{ClusterArns: m.arns}, nil
}

func (m *tagsMockECS) DescribeClusters(_ context.Context, in *ecs.DescribeClustersInput, _ ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
	var clusters []ecstypes.Cluster
	for _, arn := range in.Clusters {
		name := arn[strings.LastIndex(arn, "/")+1:]
		var tags []ecstypes.Tag
		for k, v := range m.tags[arn] {
			tags = append(tags, ecstypes.Tag{Key: awssdk.String(k), Value: awssdk.String(v)})
		}
		clusters = append(clusters, ecstypes.Cluster{
			ClusterArn:  awssdk.String(arn),
			ClusterName: awssdk.String(name),
			Tags:        tags,
		})
	}
	return &ecs.DescribeClustersOutput{Clusters: clusters}, nil
}

// Unused by tag auditing; present so tagsMockECS satisfies the full ecsAPI.
func (m *tagsMockECS) ListTaskDefinitions(_ context.Context, _ *ecs.ListTaskDefinitionsInput, _ ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error) {
	return &ecs.ListTaskDefinitionsOutput{}, nil
}

func (m *tagsMockECS) DescribeTaskDefinition(_ context.Context, _ *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	return &ecs.DescribeTaskDefinitionOutput{}, nil
}

func TestAuditECSTags(t *testing.T) {
	p := &Provider{ecs: &tagsMockECS{
		arns: []string{
			"arn:aws:ecs:us-west-2:1:cluster/web",
			"arn:aws:ecs:us-west-2:1:cluster/batch",
		},
		tags: map[string]map[string]string{
			"arn:aws:ecs:us-west-2:1:cluster/web":   {"owner": "team", "env": "prod"},
			"arn:aws:ecs:us-west-2:1:cluster/batch": {"owner": "team"}, // missing env
		},
	}}
	got, err := p.auditECSTags(context.Background(), []string{"owner", "env"})
	if err != nil {
		t.Fatalf("auditECSTags: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "batch" || got[0].ResourceType != "ecs:cluster" {
		t.Fatalf("want one ecs:cluster finding for batch, got %+v", got)
	}
	if len(got[0].MissingTags) != 1 || got[0].MissingTags[0] != "env" {
		t.Errorf("missing tags = %v, want [env]", got[0].MissingTags)
	}
}

// ── EKS (reuses mockEKS from cluster_residue_test.go) ─────────────────────────

func TestAuditEKSTags(t *testing.T) {
	p := &Provider{eks: mockEKS{
		clusters: []string{"prod", "dev"},
		clusterTags: map[string]map[string]string{
			"prod": {"owner": "team", "env": "prod"},
			"dev":  {"owner": "team"}, // missing env
		},
	}}
	got, err := p.auditEKSTags(context.Background(), []string{"owner", "env"})
	if err != nil {
		t.Fatalf("auditEKSTags: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "dev" || got[0].ResourceType != "eks:cluster" {
		t.Fatalf("want one eks:cluster finding for dev, got %+v", got)
	}
}

// ── DynamoDB ─────────────────────────────────────────────────────────────────

type mockDynamoDB struct {
	names []string
	tags  map[string]map[string]string // table name -> tags
}

func (m *mockDynamoDB) ListTables(_ context.Context, _ *dynamodb.ListTablesInput, _ ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	return &dynamodb.ListTablesOutput{TableNames: m.names}, nil
}

func (m *mockDynamoDB) DescribeTable(_ context.Context, in *dynamodb.DescribeTableInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	name := awssdk.ToString(in.TableName)
	return &dynamodb.DescribeTableOutput{Table: &ddbtypes.TableDescription{
		TableName: in.TableName,
		TableArn:  awssdk.String("arn:aws:dynamodb:us-west-2:1:table/" + name),
	}}, nil
}

func (m *mockDynamoDB) ListTagsOfResource(_ context.Context, in *dynamodb.ListTagsOfResourceInput, _ ...func(*dynamodb.Options)) (*dynamodb.ListTagsOfResourceOutput, error) {
	arn := awssdk.ToString(in.ResourceArn)
	name := arn[strings.LastIndex(arn, "/")+1:]
	var tags []ddbtypes.Tag
	for k, v := range m.tags[name] {
		tags = append(tags, ddbtypes.Tag{Key: awssdk.String(k), Value: awssdk.String(v)})
	}
	return &dynamodb.ListTagsOfResourceOutput{Tags: tags}, nil
}

func TestAuditDynamoDBTags(t *testing.T) {
	p := &Provider{dynamodb: &mockDynamoDB{
		names: []string{"orders", "sessions"},
		tags: map[string]map[string]string{
			"orders":   {"owner": "team", "env": "prod"},
			"sessions": {"owner": "team"}, // missing env
		},
	}}
	got, err := p.auditDynamoDBTags(context.Background(), []string{"owner", "env"})
	if err != nil {
		t.Fatalf("auditDynamoDBTags: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "sessions" || got[0].ResourceType != "dynamodb:table" {
		t.Fatalf("want one dynamodb:table finding for sessions, got %+v", got)
	}
}

// ── SNS ──────────────────────────────────────────────────────────────────────

type mockSNS struct {
	topicArns []string
	tags      map[string]map[string]string // topic arn -> tags
}

func (m *mockSNS) ListTopics(_ context.Context, _ *sns.ListTopicsInput, _ ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	var topics []snstypes.Topic
	for _, arn := range m.topicArns {
		topics = append(topics, snstypes.Topic{TopicArn: awssdk.String(arn)})
	}
	return &sns.ListTopicsOutput{Topics: topics}, nil
}

func (m *mockSNS) ListTagsForResource(_ context.Context, in *sns.ListTagsForResourceInput, _ ...func(*sns.Options)) (*sns.ListTagsForResourceOutput, error) {
	var tags []snstypes.Tag
	for k, v := range m.tags[awssdk.ToString(in.ResourceArn)] {
		tags = append(tags, snstypes.Tag{Key: awssdk.String(k), Value: awssdk.String(v)})
	}
	return &sns.ListTagsForResourceOutput{Tags: tags}, nil
}

func TestAuditSNSTags(t *testing.T) {
	p := &Provider{sns: &mockSNS{
		topicArns: []string{
			"arn:aws:sns:us-west-2:1:alerts",
			"arn:aws:sns:us-west-2:1:billing",
		},
		tags: map[string]map[string]string{
			"arn:aws:sns:us-west-2:1:alerts":  {"owner": "team", "env": "prod"},
			"arn:aws:sns:us-west-2:1:billing": {"owner": "team"}, // missing env
		},
	}}
	got, err := p.auditSNSTags(context.Background(), []string{"owner", "env"})
	if err != nil {
		t.Fatalf("auditSNSTags: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "billing" || got[0].ResourceType != "sns:topic" {
		t.Fatalf("want one sns:topic finding for billing (name from ARN tail), got %+v", got)
	}
}

// ── SQS (reuses mockSQS from cluster_residue_test.go) ─────────────────────────

func TestAuditSQSTags(t *testing.T) {
	p := &Provider{sqs: mockSQS{
		urls: []string{
			"https://sqs.us-west-2.amazonaws.com/1/orders",
			"https://sqs.us-west-2.amazonaws.com/1/events",
		},
		queueTags: map[string]map[string]string{
			"https://sqs.us-west-2.amazonaws.com/1/orders": {"owner": "team", "env": "prod"},
			"https://sqs.us-west-2.amazonaws.com/1/events": {"owner": "team"}, // missing env
		},
	}}
	got, err := p.auditSQSTags(context.Background(), []string{"owner", "env"})
	if err != nil {
		t.Fatalf("auditSQSTags: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "events" || got[0].ResourceType != "sqs:queue" {
		t.Fatalf("want one sqs:queue finding for events (name from URL tail), got %+v", got)
	}
}

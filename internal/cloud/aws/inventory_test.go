package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stxkxs/matlock/internal/cloud"
)

type invMockEC2 struct {
	mockEC2
	instances []ec2types.Instance
	volumes   []ec2types.Volume
}

func (m *invMockEC2) DescribeInstances(_ context.Context, _ *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: m.instances}}}, nil
}

func (m *invMockEC2) DescribeVolumes(_ context.Context, _ *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return &ec2.DescribeVolumesOutput{Volumes: m.volumes}, nil
}

type invMockS3 struct {
	mockS3
	buckets []s3types.Bucket
	err     error
}

func (m *invMockS3) ListBuckets(_ context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &s3.ListBucketsOutput{Buckets: m.buckets}, nil
}

type invMockLambda struct {
	functions []lambdatypes.FunctionConfiguration
}

func (m *invMockLambda) ListFunctions(_ context.Context, _ *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{Functions: m.functions}, nil
}
func (m *invMockLambda) ListTags(_ context.Context, _ *lambda.ListTagsInput, _ ...func(*lambda.Options)) (*lambda.ListTagsOutput, error) {
	return &lambda.ListTagsOutput{}, nil
}
func (m *invMockLambda) GetAccountSettings(_ context.Context, _ *lambda.GetAccountSettingsInput, _ ...func(*lambda.Options)) (*lambda.GetAccountSettingsOutput, error) {
	return &lambda.GetAccountSettingsOutput{}, nil
}

type invMockRDS struct{ dbs []rdstypes.DBInstance }

func (m *invMockRDS) DescribeDBInstances(_ context.Context, _ *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: m.dbs}, nil
}

type invMockECS struct {
	arns     []string
	clusters []ecstypes.Cluster
	listErr  error
}

func (m *invMockECS) ListClusters(_ context.Context, _ *ecs.ListClustersInput, _ ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return &ecs.ListClustersOutput{ClusterArns: m.arns}, nil
}
func (m *invMockECS) DescribeClusters(_ context.Context, _ *ecs.DescribeClustersInput, _ ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
	return &ecs.DescribeClustersOutput{Clusters: m.clusters}, nil
}
func (m *invMockECS) ListTaskDefinitions(_ context.Context, _ *ecs.ListTaskDefinitionsInput, _ ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error) {
	return &ecs.ListTaskDefinitionsOutput{}, nil
}
func (m *invMockECS) DescribeTaskDefinition(_ context.Context, _ *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	return &ecs.DescribeTaskDefinitionOutput{}, nil
}

type invMockELBv2 struct{ lbs []elbtypes.LoadBalancer }

func (m *invMockELBv2) DescribeLoadBalancers(_ context.Context, _ *elasticloadbalancingv2.DescribeLoadBalancersInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	return &elasticloadbalancingv2.DescribeLoadBalancersOutput{LoadBalancers: m.lbs}, nil
}
func (m *invMockELBv2) DescribeTargetGroups(_ context.Context, _ *elasticloadbalancingv2.DescribeTargetGroupsInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error) {
	return &elasticloadbalancingv2.DescribeTargetGroupsOutput{}, nil
}
func (m *invMockELBv2) DescribeTargetHealth(_ context.Context, _ *elasticloadbalancingv2.DescribeTargetHealthInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetHealthOutput, error) {
	return &elasticloadbalancingv2.DescribeTargetHealthOutput{}, nil
}

type invMockIAM struct {
	mockIAM
	roles []iamtypes.Role
}

func (m *invMockIAM) ListRoles(_ context.Context, _ *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: m.roles}, nil
}

func fullInvProvider() *Provider {
	now := time.Now()
	return &Provider{
		ec2: &invMockEC2{
			instances: []ec2types.Instance{
				{InstanceId: awssdk.String("i-1"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					LaunchTime: &now, Tags: []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("web")}}},
			},
			volumes: []ec2types.Volume{{VolumeId: awssdk.String("vol-1"), State: ec2types.VolumeStateInUse, CreateTime: &now}},
		},
		s3: &invMockS3{buckets: []s3types.Bucket{{Name: awssdk.String("b1"), CreationDate: &now}}},
		lambda: &invMockLambda{functions: []lambdatypes.FunctionConfiguration{
			{FunctionName: awssdk.String("fn1"), FunctionArn: awssdk.String("arn:fn/1"), State: lambdatypes.StateActive},
		}},
		rds: &invMockRDS{dbs: []rdstypes.DBInstance{
			{DBInstanceIdentifier: awssdk.String("db1"), DBInstanceArn: awssdk.String("arn:db/1"),
				DBInstanceStatus: awssdk.String("available"), InstanceCreateTime: &now},
		}},
		ecs: &invMockECS{
			arns:     []string{"arn:cluster/1"},
			clusters: []ecstypes.Cluster{{ClusterArn: awssdk.String("arn:cluster/1"), ClusterName: awssdk.String("c1"), Status: awssdk.String("ACTIVE")}},
		},
		elbv2: &invMockELBv2{lbs: []elbtypes.LoadBalancer{
			{LoadBalancerArn: awssdk.String("arn:lb/1"), LoadBalancerName: awssdk.String("lb1"),
				State: &elbtypes.LoadBalancerState{Code: elbtypes.LoadBalancerStateEnumActive}, CreatedTime: &now},
		}},
		iam: &invMockIAM{roles: []iamtypes.Role{{Arn: awssdk.String("arn:role/1"), RoleName: awssdk.String("admin"), CreateDate: &now}}},
	}
}

func TestListResources_All(t *testing.T) {
	p := fullInvProvider()
	got, err := p.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Expect: 1 ec2 + 1 s3 + 1 lambda + 1 ebs + 1 rds + 1 ecs + 1 elb + 1 iam = 8
	if len(got) != 8 {
		t.Errorf("expected 8 resources, got %d: %v", len(got), got)
	}
}

func TestListResources_Filter(t *testing.T) {
	p := fullInvProvider()
	got, err := p.ListResources(context.Background(), []string{"ec2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Type != "ec2:instance" {
		t.Errorf("expected only ec2:instance, got %v", got)
	}
}

func TestListResources_TypeFilterMatchesPrefix(t *testing.T) {
	p := fullInvProvider()
	got, _ := p.ListResources(context.Background(), []string{"s3:bucket"})
	if len(got) != 1 || got[0].Type != "s3:bucket" {
		t.Errorf("expected only s3:bucket: got %v", got)
	}
}

func TestListResources_S3ErrorBubblesUp(t *testing.T) {
	p := fullInvProvider()
	p.s3 = &invMockS3{err: errors.New("auth fail")}
	_, err := p.ListResources(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestListResources_KindAssignment(t *testing.T) {
	p := fullInvProvider()
	got, _ := p.ListResources(context.Background(), nil)
	wantKinds := map[string]cloud.ResourceKind{
		"ec2:instance":     cloud.ResourceCompute,
		"s3:bucket":        cloud.ResourceStorage,
		"lambda:function":  cloud.ResourceServerless,
		"ebs:volume":       cloud.ResourceStorage,
		"rds:db":           cloud.ResourceDatabase,
		"ecs:cluster":      cloud.ResourceContainer,
		"elb:loadbalancer": cloud.ResourceLoadBalancer,
		"iam:role":         cloud.ResourceIAM,
	}
	for _, r := range got {
		if want, ok := wantKinds[r.Type]; ok && r.Kind != want {
			t.Errorf("type %q kind: got %v, want %v", r.Type, r.Kind, want)
		}
	}
}

func TestEC2TagValue(t *testing.T) {
	tags := []ec2types.Tag{
		{Key: awssdk.String("env"), Value: awssdk.String("prod")},
		{Key: awssdk.String("Name"), Value: awssdk.String("web")},
	}
	if got := ec2TagValue(tags, "Name"); got != "web" {
		t.Errorf("got %q", got)
	}
	if got := ec2TagValue(tags, "missing"); got != "" {
		t.Errorf("got %q for missing tag, want empty", got)
	}
}

func TestEC2TagsToMap(t *testing.T) {
	got := ec2TagsToMap([]ec2types.Tag{
		{Key: awssdk.String("k1"), Value: awssdk.String("v1")},
		{Key: awssdk.String("k2"), Value: awssdk.String("v2")},
	})
	if len(got) != 2 || got["k1"] != "v1" || got["k2"] != "v2" {
		t.Errorf("got %v", got)
	}
	if ec2TagsToMap(nil) != nil {
		t.Error("nil input should return nil")
	}
}

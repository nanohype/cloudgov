package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stxkxs/matlock/internal/cloud"
)

type tagsMockEC2 struct {
	mockEC2
	instances    []ec2types.Instance
	instancesErr error
}

func (m *tagsMockEC2) DescribeInstances(_ context.Context, _ *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if m.instancesErr != nil {
		return nil, m.instancesErr
	}
	return &ec2.DescribeInstancesOutput{
		Reservations: []ec2types.Reservation{{Instances: m.instances}},
	}, nil
}

type mockRDS struct {
	dbs []rdstypes.DBInstance
	err error
}

func (m *mockRDS) DescribeDBInstances(_ context.Context, _ *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &rds.DescribeDBInstancesOutput{DBInstances: m.dbs}, nil
}

type mockLambda struct {
	functions []lambdatypes.FunctionConfiguration
	tags      map[string]map[string]string // arn -> tags
	listErr   error
	tagsErr   error
}

func (m *mockLambda) ListFunctions(_ context.Context, _ *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return &lambda.ListFunctionsOutput{Functions: m.functions}, nil
}

func (m *mockLambda) ListTags(_ context.Context, in *lambda.ListTagsInput, _ ...func(*lambda.Options)) (*lambda.ListTagsOutput, error) {
	if m.tagsErr != nil {
		return nil, m.tagsErr
	}
	return &lambda.ListTagsOutput{Tags: m.tags[awssdk.ToString(in.Resource)]}, nil
}

func (m *mockLambda) GetAccountSettings(_ context.Context, _ *lambda.GetAccountSettingsInput, _ ...func(*lambda.Options)) (*lambda.GetAccountSettingsOutput, error) {
	return &lambda.GetAccountSettingsOutput{}, nil
}

func (m *mockLambda) GetPolicy(_ context.Context, _ *lambda.GetPolicyInput, _ ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	return &lambda.GetPolicyOutput{}, nil
}

// tagsMockS3 satisfies s3API with tagging support.
type tagsMockS3 struct {
	buckets    []s3types.Bucket
	tagSets    map[string][]s3types.Tag
	listErr    error
	taggingErr error
}

func (m *tagsMockS3) ListBuckets(_ context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return &s3.ListBucketsOutput{Buckets: m.buckets}, nil
}
func (m *tagsMockS3) GetBucketLocation(_ context.Context, _ *s3.GetBucketLocationInput, _ ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	return &s3.GetBucketLocationOutput{}, nil
}
func (m *tagsMockS3) GetPublicAccessBlock(_ context.Context, _ *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	return &s3.GetPublicAccessBlockOutput{}, nil
}
func (m *tagsMockS3) GetBucketEncryption(_ context.Context, _ *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	return &s3.GetBucketEncryptionOutput{}, nil
}
func (m *tagsMockS3) GetBucketVersioning(_ context.Context, _ *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return &s3.GetBucketVersioningOutput{}, nil
}
func (m *tagsMockS3) GetBucketLogging(_ context.Context, _ *s3.GetBucketLoggingInput, _ ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	return &s3.GetBucketLoggingOutput{}, nil
}
func (m *tagsMockS3) GetBucketTagging(_ context.Context, in *s3.GetBucketTaggingInput, _ ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	if m.taggingErr != nil {
		return nil, m.taggingErr
	}
	return &s3.GetBucketTaggingOutput{TagSet: m.tagSets[awssdk.ToString(in.Bucket)]}, nil
}
func (m *tagsMockS3) HeadBucket(_ context.Context, _ *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, nil
}

func TestAuditTags_NoRequiredReturnsEmpty(t *testing.T) {
	p := &Provider{}
	got, err := p.AuditTags(context.Background(), nil)
	if err != nil || got != nil {
		t.Errorf("expected (nil, nil), got (%v, %v)", got, err)
	}
}

func TestAuditTags_EC2(t *testing.T) {
	mock := &tagsMockEC2{
		instances: []ec2types.Instance{
			{
				InstanceId: awssdk.String("i-1"),
				Tags: []ec2types.Tag{
					{Key: awssdk.String("owner"), Value: awssdk.String("team")},
				},
			},
			{
				InstanceId: awssdk.String("i-2"),
				Tags: []ec2types.Tag{
					{Key: awssdk.String("owner"), Value: awssdk.String("team")},
					{Key: awssdk.String("env"), Value: awssdk.String("prod")},
				},
			},
		},
	}
	s3Mock := &tagsMockS3{}
	p := &Provider{
		ec2:         mock,
		s3:          s3Mock,
		s3ForRegion: func(_ string) s3API { return s3Mock },
		rds:         &mockRDS{},
		lambda:      &mockLambda{},
	}
	got, err := p.AuditTags(context.Background(), []string{"owner", "env"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "i-1" || len(got[0].MissingTags) != 1 || got[0].MissingTags[0] != "env" {
		t.Errorf("expected 1 finding for i-1 missing env, got %v", got)
	}
}

func TestAuditTags_S3(t *testing.T) {
	s3Mock := &tagsMockS3{
		buckets: []s3types.Bucket{{Name: awssdk.String("bucket-1")}},
		tagSets: map[string][]s3types.Tag{
			"bucket-1": {{Key: awssdk.String("owner"), Value: awssdk.String("x")}},
		},
	}
	p := &Provider{
		ec2:         &tagsMockEC2{},
		s3:          s3Mock,
		s3ForRegion: func(_ string) s3API { return s3Mock },
		rds:         &mockRDS{},
		lambda:      &mockLambda{},
	}
	got, err := p.AuditTags(context.Background(), []string{"owner", "env"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "bucket-1" || got[0].ResourceType != "s3:bucket" {
		t.Errorf("expected one finding for bucket-1: got %v", got)
	}
}

func TestAuditTags_RDS(t *testing.T) {
	p := &Provider{
		ec2:         &tagsMockEC2{},
		s3:          &tagsMockS3{},
		s3ForRegion: func(_ string) s3API { return &tagsMockS3{} },
		rds: &mockRDS{dbs: []rdstypes.DBInstance{
			{DBInstanceIdentifier: awssdk.String("db-1"),
				TagList: []rdstypes.Tag{{Key: awssdk.String("owner"), Value: awssdk.String("x")}}},
		}},
		lambda: &mockLambda{},
	}
	got, err := p.AuditTags(context.Background(), []string{"owner", "env"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "db-1" || got[0].ResourceType != "rds:db" {
		t.Errorf("expected one finding for db-1: got %v", got)
	}
}

func TestAuditTags_Lambda(t *testing.T) {
	p := &Provider{
		ec2:         &tagsMockEC2{},
		s3:          &tagsMockS3{},
		s3ForRegion: func(_ string) s3API { return &tagsMockS3{} },
		rds:         &mockRDS{},
		lambda: &mockLambda{
			functions: []lambdatypes.FunctionConfiguration{
				{FunctionName: awssdk.String("fn-1"), FunctionArn: awssdk.String("arn:fn/1")},
			},
			tags: map[string]map[string]string{
				"arn:fn/1": {"owner": "x"},
			},
		},
	}
	got, err := p.AuditTags(context.Background(), []string{"owner", "env"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "fn-1" || got[0].ResourceType != "lambda:function" {
		t.Errorf("expected one finding for fn-1: got %v", got)
	}
}

func TestAuditTags_ErrorBubblesUp(t *testing.T) {
	p := &Provider{
		ec2: &tagsMockEC2{instancesErr: errors.New("auth fail")},
		s3:  &tagsMockS3{}, s3ForRegion: func(_ string) s3API { return &tagsMockS3{} },
		rds: &mockRDS{}, lambda: &mockLambda{},
	}
	_, err := p.AuditTags(context.Background(), []string{"owner"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMissingTags(t *testing.T) {
	have := map[string]struct{}{"owner": {}, "env": {}}
	got := missingTags([]string{"owner", "env", "cost-center"}, have)
	if len(got) != 1 || got[0] != "cost-center" {
		t.Errorf("got %v, want [cost-center]", got)
	}
	got = missingTags([]string{"owner"}, have)
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// Compile-time check that cloud package types are reachable.
var _ = cloud.SeverityMedium

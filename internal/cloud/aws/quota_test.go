package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type quotaMockEC2 struct {
	mockEC2
	addresses []ec2types.Address
	vpcs      []ec2types.Vpc
	igws      []ec2types.InternetGateway
	sgs       []ec2types.SecurityGroup
}

func (m *quotaMockEC2) DescribeAddresses(_ context.Context, _ *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return &ec2.DescribeAddressesOutput{Addresses: m.addresses}, nil
}
func (m *quotaMockEC2) DescribeVpcs(_ context.Context, _ *ec2.DescribeVpcsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	return &ec2.DescribeVpcsOutput{Vpcs: m.vpcs}, nil
}
func (m *quotaMockEC2) DescribeInternetGateways(_ context.Context, _ *ec2.DescribeInternetGatewaysInput, _ ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error) {
	return &ec2.DescribeInternetGatewaysOutput{InternetGateways: m.igws}, nil
}
func (m *quotaMockEC2) DescribeSecurityGroups(_ context.Context, _ *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: m.sgs}, nil
}

type quotaMockIAM struct {
	mockIAM
	summary map[string]int32
}

func (m *quotaMockIAM) GetAccountSummary(_ context.Context, _ *iam.GetAccountSummaryInput, _ ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return &iam.GetAccountSummaryOutput{SummaryMap: m.summary}, nil
}

type quotaMockLambda struct {
	limit *lambdatypes.AccountLimit
	usage *lambdatypes.AccountUsage
	fns   []lambdatypes.FunctionConfiguration
}

func (m *quotaMockLambda) ListFunctions(_ context.Context, _ *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{Functions: m.fns}, nil
}
func (m *quotaMockLambda) ListTags(_ context.Context, _ *lambda.ListTagsInput, _ ...func(*lambda.Options)) (*lambda.ListTagsOutput, error) {
	return &lambda.ListTagsOutput{}, nil
}
func (m *quotaMockLambda) GetAccountSettings(_ context.Context, _ *lambda.GetAccountSettingsInput, _ ...func(*lambda.Options)) (*lambda.GetAccountSettingsOutput, error) {
	return &lambda.GetAccountSettingsOutput{
		AccountLimit: m.limit,
		AccountUsage: m.usage,
	}, nil
}

func TestIAMQuotas(t *testing.T) {
	p := &Provider{iam: &quotaMockIAM{summary: map[string]int32{
		"Users":      10,
		"UsersQuota": 100,
		"Roles":      50,
		"RolesQuota": 1000,
	}}}
	got, err := p.iamQuotas(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 quotas (users + roles), got %d: %v", len(got), got)
	}
	byName := map[string]float64{}
	for _, q := range got {
		byName[q.QuotaName] = q.Utilization
	}
	if byName["Users"] != 10.0 {
		t.Errorf("Users utilization: got %v, want 10.0", byName["Users"])
	}
}

func TestIAMQuotas_Error(t *testing.T) {
	p := &Provider{iam: &errorIAM{err: errors.New("auth")}}
	_, err := p.iamQuotas(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

type errorIAM struct {
	mockIAM
	err error
}

func (m *errorIAM) GetAccountSummary(_ context.Context, _ *iam.GetAccountSummaryInput, _ ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return nil, m.err
}

func TestEC2Quotas(t *testing.T) {
	p := &Provider{ec2: &quotaMockEC2{
		addresses: []ec2types.Address{{AllocationId: awssdk.String("eip-1")}, {AllocationId: awssdk.String("eip-2")}},
		vpcs:      []ec2types.Vpc{{VpcId: awssdk.String("vpc-1")}},
		igws:      []ec2types.InternetGateway{{InternetGatewayId: awssdk.String("igw-1")}},
		sgs:       []ec2types.SecurityGroup{{GroupId: awssdk.String("sg-1")}},
	}}
	got, err := p.ec2Quotas(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("expected 4 quotas, got %d", len(got))
	}
	byName := map[string]float64{}
	for _, q := range got {
		byName[q.QuotaName] = q.Used
	}
	if byName["Elastic IPs"] != 2 {
		t.Errorf("EIPs used: got %v, want 2", byName["Elastic IPs"])
	}
}

func TestS3Quotas(t *testing.T) {
	p := &Provider{s3: &invMockS3{buckets: s3FakeBucketSlice(3)}}
	got, err := p.s3Quotas(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Used != 3 {
		t.Errorf("got %v", got)
	}
}

func s3FakeBucketSlice(n int) []s3types.Bucket {
	out := make([]s3types.Bucket, n)
	for i := 0; i < n; i++ {
		out[i] = s3types.Bucket{Name: awssdk.String("b")}
	}
	return out
}

func TestLambdaQuotas_NoLimits(t *testing.T) {
	p := &Provider{lambda: &quotaMockLambda{}}
	got, err := p.lambdaQuotas(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no quotas when limits missing: got %v", got)
	}
}

func TestLambdaQuotas_WithLimits(t *testing.T) {
	p := &Provider{lambda: &quotaMockLambda{
		limit: &lambdatypes.AccountLimit{ConcurrentExecutions: 1000, TotalCodeSize: 75_000_000_000},
		usage: &lambdatypes.AccountUsage{TotalCodeSize: 1_000_000},
		fns: []lambdatypes.FunctionConfiguration{
			{FunctionName: awssdk.String("fn1")},
		},
	}}
	got, _ := p.lambdaQuotas(context.Background())
	if len(got) != 2 {
		t.Errorf("expected 2 quotas (functions + code storage), got %d", len(got))
	}
}

func TestRDSQuotas(t *testing.T) {
	p := &Provider{rds: &invMockRDS{dbs: nil}}
	got, err := p.rdsQuotas(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Used != 0 {
		t.Errorf("got %v", got)
	}
}

func TestPct(t *testing.T) {
	if pct(0, 0) != 0 {
		t.Error("divide by zero should be 0")
	}
	if pct(50, 100) != 50 {
		t.Error("50/100 should be 50%")
	}
	if pct(100, 100) != 100 {
		t.Error("100/100 should be 100%")
	}
}

func TestListQuotas_AggregatesAll(t *testing.T) {
	p := &Provider{
		iam: &quotaMockIAM{summary: map[string]int32{"Users": 1, "UsersQuota": 100}},
		ec2: &quotaMockEC2{},
		s3:  &invMockS3{buckets: s3FakeBucketSlice(2)},
		lambda: &quotaMockLambda{
			limit: &lambdatypes.AccountLimit{ConcurrentExecutions: 1000, TotalCodeSize: 1000},
			usage: &lambdatypes.AccountUsage{TotalCodeSize: 100},
		},
		rds: &invMockRDS{},
	}
	got, _ := p.ListQuotas(context.Background())
	// IAM(1) + EC2(4) + S3(1) + Lambda(2) + RDS(1) = 9
	if len(got) != 9 {
		t.Errorf("expected 9 quotas, got %d", len(got))
	}
}

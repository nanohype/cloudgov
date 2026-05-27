package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stxkxs/matlock/internal/cloud"
)

// driftMockEC2 supports both DescribeSecurityGroups (for SG drift) and
// DescribeInstances (for EC2 instance drift).
type driftMockEC2 struct {
	mockEC2
	sgs       []ec2types.SecurityGroup
	sgErr     error
	instances []ec2types.Instance
	instErr   error
}

func (m *driftMockEC2) DescribeSecurityGroups(_ context.Context, _ *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if m.sgErr != nil {
		return nil, m.sgErr
	}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: m.sgs}, nil
}

func (m *driftMockEC2) DescribeInstances(_ context.Context, _ *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if m.instErr != nil {
		return nil, m.instErr
	}
	if len(m.instances) == 0 {
		return &ec2.DescribeInstancesOutput{}, nil
	}
	return &ec2.DescribeInstancesOutput{
		Reservations: []ec2types.Reservation{{Instances: m.instances}},
	}, nil
}

// driftMockS3 stores responses for HeadBucket, GetBucketVersioning, GetPublicAccessBlock.
type driftMockS3 struct {
	mockS3
	headErr     error
	versioning  s3types.BucketVersioningStatus
	pubBlock    *s3types.PublicAccessBlockConfiguration
	pubBlockErr error
}

func (m *driftMockS3) HeadBucket(_ context.Context, _ *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if m.headErr != nil {
		return nil, m.headErr
	}
	return &s3.HeadBucketOutput{}, nil
}
func (m *driftMockS3) GetBucketVersioning(_ context.Context, _ *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return &s3.GetBucketVersioningOutput{Status: m.versioning}, nil
}
func (m *driftMockS3) GetPublicAccessBlock(_ context.Context, _ *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if m.pubBlockErr != nil {
		return nil, m.pubBlockErr
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: m.pubBlock}, nil
}

type driftMockIAM struct {
	mockIAM
	policyDesc string
	policyErr  error
}

func (m *driftMockIAM) GetPolicy(_ context.Context, _ *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	if m.policyErr != nil {
		return nil, m.policyErr
	}
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{
		Description: awssdk.String(m.policyDesc),
		Path:        awssdk.String("/"),
	}}, nil
}

// Need full iam import alias for the override above:

type driftMockRDS struct {
	instance *rdstypes.DBInstance
	err      error
}

func (m *driftMockRDS) DescribeDBInstances(_ context.Context, _ *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.instance == nil {
		return &rds.DescribeDBInstancesOutput{}, nil
	}
	return &rds.DescribeDBInstancesOutput{DBInstances: []rdstypes.DBInstance{*m.instance}}, nil
}

type driftMockELBv2 struct {
	lb  *elbtypes.LoadBalancer
	err error
}

func (m *driftMockELBv2) DescribeLoadBalancers(_ context.Context, _ *elasticloadbalancingv2.DescribeLoadBalancersInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.lb == nil {
		return &elasticloadbalancingv2.DescribeLoadBalancersOutput{}, nil
	}
	return &elasticloadbalancingv2.DescribeLoadBalancersOutput{LoadBalancers: []elbtypes.LoadBalancer{*m.lb}}, nil
}
func (m *driftMockELBv2) DescribeTargetGroups(_ context.Context, _ *elasticloadbalancingv2.DescribeTargetGroupsInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error) {
	return &elasticloadbalancingv2.DescribeTargetGroupsOutput{}, nil
}
func (m *driftMockELBv2) DescribeTargetHealth(_ context.Context, _ *elasticloadbalancingv2.DescribeTargetHealthInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetHealthOutput, error) {
	return &elasticloadbalancingv2.DescribeTargetHealthOutput{}, nil
}

func TestSupportedResourceTypes(t *testing.T) {
	p := &Provider{}
	got := p.SupportedResourceTypes()
	wantSubset := []string{"aws_security_group", "aws_iam_policy", "aws_s3_bucket"}
	for _, w := range wantSubset {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q in supported types: %v", w, got)
		}
	}
}

func TestCheckDrift_UnsupportedResourceType(t *testing.T) {
	p := &Provider{}
	got, err := p.CheckDrift(context.Background(), "aws_widget", "x", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != cloud.DriftError {
		t.Errorf("status: got %v, want DriftError", got.Status)
	}
}

func TestCheckSGDrift_InSync(t *testing.T) {
	p := &Provider{ec2: &driftMockEC2{sgs: []ec2types.SecurityGroup{
		{GroupId: awssdk.String("sg-1"), GroupName: awssdk.String("web"), Description: awssdk.String("web tier")},
	}}}
	got, err := p.CheckDrift(context.Background(), "aws_security_group", "sg-1",
		map[string]interface{}{"name": "web", "description": "web tier"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != cloud.DriftInSync {
		t.Errorf("status: got %v, want DriftInSync", got.Status)
	}
}

func TestCheckSGDrift_Modified(t *testing.T) {
	p := &Provider{ec2: &driftMockEC2{sgs: []ec2types.SecurityGroup{
		{GroupId: awssdk.String("sg-1"), GroupName: awssdk.String("changed"), Description: awssdk.String("web tier")},
	}}}
	got, _ := p.CheckDrift(context.Background(), "aws_security_group", "sg-1",
		map[string]interface{}{"name": "web", "description": "web tier"})
	if got.Status != cloud.DriftModified {
		t.Errorf("status: got %v, want DriftModified", got.Status)
	}
}

func TestCheckSGDrift_Deleted(t *testing.T) {
	p := &Provider{ec2: &driftMockEC2{sgs: nil}}
	got, _ := p.CheckDrift(context.Background(), "aws_security_group", "sg-missing",
		map[string]interface{}{"name": "web"})
	if got.Status != cloud.DriftDeleted {
		t.Errorf("status: got %v, want DriftDeleted", got.Status)
	}
}

func TestCheckSGDrift_APIError(t *testing.T) {
	p := &Provider{ec2: &driftMockEC2{sgErr: errors.New("throttled")}}
	_, err := p.CheckDrift(context.Background(), "aws_security_group", "sg-1", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCheckIAMPolicyDrift_DeletedOnNoSuchEntity(t *testing.T) {
	p := &Provider{iam: &driftMockIAM{policyErr: &apiErr{code: "NoSuchEntity"}}}
	got, err := p.CheckDrift(context.Background(), "aws_iam_policy", "arn:policy/1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != cloud.DriftDeleted {
		t.Errorf("status: got %v, want DriftDeleted", got.Status)
	}
}

func TestCheckIAMPolicyDrift_InSync(t *testing.T) {
	p := &Provider{iam: &driftMockIAM{policyDesc: "managed"}}
	got, _ := p.CheckDrift(context.Background(), "aws_iam_policy", "arn:policy/1",
		map[string]interface{}{"description": "managed", "path": "/"})
	if got.Status != cloud.DriftInSync {
		t.Errorf("status: got %v, want DriftInSync", got.Status)
	}
}

func TestCheckS3BucketDrift_DeletedOnHeadFailure(t *testing.T) {
	p := &Provider{s3: &driftMockS3{headErr: errors.New("not found")}}
	got, _ := p.CheckDrift(context.Background(), "aws_s3_bucket", "missing", nil)
	if got.Status != cloud.DriftDeleted {
		t.Errorf("status: got %v, want DriftDeleted", got.Status)
	}
}

func TestCheckS3BucketDrift_InSync(t *testing.T) {
	p := &Provider{s3: &driftMockS3{versioning: s3types.BucketVersioningStatusEnabled}}
	got, _ := p.CheckDrift(context.Background(), "aws_s3_bucket", "mybucket",
		map[string]interface{}{"bucket": "mybucket"})
	if got.Status != cloud.DriftInSync {
		t.Errorf("status: got %v, want DriftInSync", got.Status)
	}
}

func TestCheckEC2InstanceDrift_Modified(t *testing.T) {
	p := &Provider{ec2: &driftMockEC2{instances: []ec2types.Instance{
		{InstanceType: ec2types.InstanceTypeT3Large, KeyName: awssdk.String("prod-key")},
	}}}
	got, _ := p.CheckDrift(context.Background(), "aws_instance", "i-1",
		map[string]interface{}{"instance_type": "t3.medium", "key_name": "prod-key"})
	if got.Status != cloud.DriftModified {
		t.Errorf("status: got %v, want DriftModified", got.Status)
	}
}

func TestCheckEC2InstanceDrift_Deleted(t *testing.T) {
	p := &Provider{ec2: &driftMockEC2{instances: nil}}
	got, _ := p.CheckDrift(context.Background(), "aws_instance", "i-1",
		map[string]interface{}{"instance_type": "t3.medium"})
	if got.Status != cloud.DriftDeleted {
		t.Errorf("status: got %v, want DriftDeleted", got.Status)
	}
}

func TestCheckRDSInstanceDrift_InSync(t *testing.T) {
	p := &Provider{rds: &driftMockRDS{instance: &rdstypes.DBInstance{
		DBInstanceClass: awssdk.String("db.t3.medium"),
		EngineVersion:   awssdk.String("8.0.32"),
	}}}
	got, _ := p.CheckDrift(context.Background(), "aws_db_instance", "mydb",
		map[string]interface{}{"instance_class": "db.t3.medium", "engine_version": "8.0.32"})
	if got.Status != cloud.DriftInSync {
		t.Errorf("status: got %v, want DriftInSync", got.Status)
	}
}

func TestCheckELBDrift_Modified(t *testing.T) {
	p := &Provider{elbv2: &driftMockELBv2{lb: &elbtypes.LoadBalancer{
		Type:   elbtypes.LoadBalancerTypeEnumApplication,
		Scheme: elbtypes.LoadBalancerSchemeEnumInternal,
	}}}
	got, _ := p.CheckDrift(context.Background(), "aws_lb", "arn:lb/1",
		map[string]interface{}{"load_balancer_type": "network", "internal": "true"})
	if got.Status != cloud.DriftModified {
		t.Errorf("status: got %v, want DriftModified", got.Status)
	}
}

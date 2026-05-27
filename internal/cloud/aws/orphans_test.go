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
	"github.com/stxkxs/matlock/internal/cloud"
)

type mockEC2 struct {
	volumePages   [][]ec2types.Volume
	addressesOut  []ec2types.Address
	volumesErr    error
	addressesErr  error
	volumesCalls  int
	addressesCall int
}

func (m *mockEC2) DescribeVolumes(_ context.Context, _ *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if m.volumesErr != nil {
		return nil, m.volumesErr
	}
	idx := m.volumesCalls
	m.volumesCalls++
	if idx >= len(m.volumePages) {
		return &ec2.DescribeVolumesOutput{}, nil
	}
	var token *string
	if idx+1 < len(m.volumePages) {
		token = awssdk.String("next")
	}
	return &ec2.DescribeVolumesOutput{
		Volumes:   m.volumePages[idx],
		NextToken: token,
	}, nil
}

func (m *mockEC2) DescribeAddresses(_ context.Context, _ *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	m.addressesCall++
	if m.addressesErr != nil {
		return nil, m.addressesErr
	}
	return &ec2.DescribeAddressesOutput{Addresses: m.addressesOut}, nil
}

// Default no-op implementations so mockEC2 satisfies the full ec2API surface.
// Tests that exercise these methods embed mockEC2 and override.
func (m *mockEC2) DescribeSecurityGroups(_ context.Context, _ *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{}, nil
}

func (m *mockEC2) DescribeInstances(_ context.Context, _ *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{}, nil
}

func (m *mockEC2) DescribeInstanceAttribute(_ context.Context, _ *ec2.DescribeInstanceAttributeInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceAttributeOutput, error) {
	return &ec2.DescribeInstanceAttributeOutput{}, nil
}

func (m *mockEC2) DescribeVpcs(_ context.Context, _ *ec2.DescribeVpcsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	return &ec2.DescribeVpcsOutput{}, nil
}

func (m *mockEC2) DescribeInternetGateways(_ context.Context, _ *ec2.DescribeInternetGatewaysInput, _ ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error) {
	return &ec2.DescribeInternetGatewaysOutput{}, nil
}

type mockELBv2 struct {
	lbPages           [][]elbtypes.LoadBalancer
	targetGroups      map[string][]elbtypes.TargetGroup             // lbArn -> tgs
	targetHealth      map[string][]elbtypes.TargetHealthDescription // tgArn -> healths
	lbErr             error
	tgErr             error
	healthErr         error
	lbCalls           int
	tgCalls           int
	healthCalls       int
	tgErrForLBARN     string
	healthErrForTGARN string
}

func (m *mockELBv2) DescribeLoadBalancers(_ context.Context, _ *elasticloadbalancingv2.DescribeLoadBalancersInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	if m.lbErr != nil {
		return nil, m.lbErr
	}
	idx := m.lbCalls
	m.lbCalls++
	if idx >= len(m.lbPages) {
		return &elasticloadbalancingv2.DescribeLoadBalancersOutput{}, nil
	}
	var marker *string
	if idx+1 < len(m.lbPages) {
		marker = awssdk.String("next")
	}
	return &elasticloadbalancingv2.DescribeLoadBalancersOutput{
		LoadBalancers: m.lbPages[idx],
		NextMarker:    marker,
	}, nil
}

func (m *mockELBv2) DescribeTargetGroups(_ context.Context, in *elasticloadbalancingv2.DescribeTargetGroupsInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error) {
	m.tgCalls++
	arn := awssdk.ToString(in.LoadBalancerArn)
	if m.tgErrForLBARN != "" && m.tgErrForLBARN == arn {
		return nil, errors.New("tg lookup failed")
	}
	if m.tgErr != nil {
		return nil, m.tgErr
	}
	return &elasticloadbalancingv2.DescribeTargetGroupsOutput{
		TargetGroups: m.targetGroups[arn],
	}, nil
}

func (m *mockELBv2) DescribeTargetHealth(_ context.Context, in *elasticloadbalancingv2.DescribeTargetHealthInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetHealthOutput, error) {
	m.healthCalls++
	arn := awssdk.ToString(in.TargetGroupArn)
	if m.healthErrForTGARN != "" && m.healthErrForTGARN == arn {
		return nil, errors.New("health lookup failed")
	}
	if m.healthErr != nil {
		return nil, m.healthErr
	}
	return &elasticloadbalancingv2.DescribeTargetHealthOutput{
		TargetHealthDescriptions: m.targetHealth[arn],
	}, nil
}

// ── orphanDisks ───────────────────────────────────────────────────────────────

func TestOrphanDisks(t *testing.T) {
	tests := []struct {
		name      string
		mock      *mockEC2
		wantIDs   []string
		wantSizes []int32
	}{
		{
			name: "single available volume",
			mock: &mockEC2{
				volumePages: [][]ec2types.Volume{{
					{VolumeId: awssdk.String("vol-1"), Size: awssdk.Int32(100), VolumeType: ec2types.VolumeTypeGp3,
						Tags: []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("orphan-disk")}}},
				}},
			},
			wantIDs:   []string{"vol-1"},
			wantSizes: []int32{100},
		},
		{
			name: "multiple pages accumulate",
			mock: &mockEC2{
				volumePages: [][]ec2types.Volume{
					{{VolumeId: awssdk.String("vol-1"), Size: awssdk.Int32(50)}},
					{{VolumeId: awssdk.String("vol-2"), Size: awssdk.Int32(200)}},
				},
			},
			wantIDs:   []string{"vol-1", "vol-2"},
			wantSizes: []int32{50, 200},
		},
		{
			name:    "pagination error returns volumes collected before error (warn-and-break)",
			mock:    &mockEC2{volumesErr: errors.New("throttled")},
			wantIDs: []string{},
		},
		{
			name:    "no volumes returns empty",
			mock:    &mockEC2{},
			wantIDs: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{ec2: tt.mock}
			got, err := p.orphanDisks(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotIDs := make([]string, 0, len(got))
			for _, o := range got {
				gotIDs = append(gotIDs, o.ID)
				if o.Kind != cloud.OrphanDisk {
					t.Errorf("kind: got %v, want %v", o.Kind, cloud.OrphanDisk)
				}
				if o.Provider != "aws" {
					t.Errorf("provider: got %q", o.Provider)
				}
			}
			if !equalStrings(gotIDs, tt.wantIDs) {
				t.Errorf("ids: got %v, want %v", gotIDs, tt.wantIDs)
			}
		})
	}
}

func TestOrphanDisks_CostEstimation(t *testing.T) {
	// 100 GB * $0.10/GB = $10
	p := &Provider{ec2: &mockEC2{
		volumePages: [][]ec2types.Volume{{
			{VolumeId: awssdk.String("vol-1"), Size: awssdk.Int32(100)},
		}},
	}}
	got, _ := p.orphanDisks(context.Background())
	if len(got) != 1 || got[0].MonthlyCost != 10.0 {
		t.Errorf("cost: got %v", got)
	}
}

func TestVolumeName(t *testing.T) {
	tests := []struct {
		name string
		v    ec2types.Volume
		want string
	}{
		{"with Name tag", ec2types.Volume{VolumeId: awssdk.String("vol-1"),
			Tags: []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("data-disk")}}}, "data-disk"},
		{"without Name tag falls back to ID", ec2types.Volume{VolumeId: awssdk.String("vol-1")}, "vol-1"},
		{"Name tag among other tags", ec2types.Volume{VolumeId: awssdk.String("vol-1"),
			Tags: []ec2types.Tag{
				{Key: awssdk.String("env"), Value: awssdk.String("prod")},
				{Key: awssdk.String("Name"), Value: awssdk.String("data-disk")},
			}}, "data-disk"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := volumeName(tt.v)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// ── orphanIPs ─────────────────────────────────────────────────────────────────

func TestOrphanIPs(t *testing.T) {
	tests := []struct {
		name    string
		mock    *mockEC2
		wantIDs []string
		wantErr bool
	}{
		{
			name: "unassociated EIP is reported",
			mock: &mockEC2{addressesOut: []ec2types.Address{
				{AllocationId: awssdk.String("eipalloc-1"), PublicIp: awssdk.String("1.2.3.4")},
			}},
			wantIDs: []string{"eipalloc-1"},
		},
		{
			name: "associated EIP is skipped",
			mock: &mockEC2{addressesOut: []ec2types.Address{
				{AllocationId: awssdk.String("eipalloc-1"), PublicIp: awssdk.String("1.2.3.4"),
					AssociationId: awssdk.String("eipassoc-1")},
			}},
			wantIDs: []string{},
		},
		{
			name:    "API error is wrapped and returned",
			mock:    &mockEC2{addressesErr: errors.New("auth fail")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{ec2: tt.mock}
			got, err := p.orphanIPs(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			gotIDs := make([]string, 0, len(got))
			for _, o := range got {
				gotIDs = append(gotIDs, o.ID)
			}
			if !equalStrings(gotIDs, tt.wantIDs) {
				t.Errorf("ids: got %v, want %v", gotIDs, tt.wantIDs)
			}
		})
	}
}

// ── orphanLoadBalancers ───────────────────────────────────────────────────────

func TestOrphanLoadBalancers(t *testing.T) {
	tests := []struct {
		name    string
		mock    *mockELBv2
		wantIDs []string
	}{
		{
			name: "LB with no target groups is orphan",
			mock: &mockELBv2{
				lbPages: [][]elbtypes.LoadBalancer{{
					{LoadBalancerArn: awssdk.String("arn:lb/1"), LoadBalancerName: awssdk.String("empty-lb"),
						Type: elbtypes.LoadBalancerTypeEnumApplication},
				}},
				targetGroups: map[string][]elbtypes.TargetGroup{},
			},
			wantIDs: []string{"arn:lb/1"},
		},
		{
			name: "LB with target groups but no healthy targets is orphan",
			mock: &mockELBv2{
				lbPages: [][]elbtypes.LoadBalancer{{
					{LoadBalancerArn: awssdk.String("arn:lb/1"), LoadBalancerName: awssdk.String("idle-lb"),
						Type: elbtypes.LoadBalancerTypeEnumNetwork},
				}},
				targetGroups: map[string][]elbtypes.TargetGroup{
					"arn:lb/1": {{TargetGroupArn: awssdk.String("arn:tg/1")}},
				},
				targetHealth: map[string][]elbtypes.TargetHealthDescription{
					"arn:tg/1": nil, // empty
				},
			},
			wantIDs: []string{"arn:lb/1"},
		},
		{
			name: "LB with healthy targets is NOT orphan",
			mock: &mockELBv2{
				lbPages: [][]elbtypes.LoadBalancer{{
					{LoadBalancerArn: awssdk.String("arn:lb/1"), LoadBalancerName: awssdk.String("busy-lb")},
				}},
				targetGroups: map[string][]elbtypes.TargetGroup{
					"arn:lb/1": {{TargetGroupArn: awssdk.String("arn:tg/1")}},
				},
				targetHealth: map[string][]elbtypes.TargetHealthDescription{
					"arn:tg/1": {{Target: &elbtypes.TargetDescription{Id: awssdk.String("i-123")}}},
				},
			},
			wantIDs: []string{},
		},
		{
			name: "LB with nil ARN is skipped",
			mock: &mockELBv2{
				lbPages: [][]elbtypes.LoadBalancer{{
					{LoadBalancerName: awssdk.String("ghost-lb")},
				}},
			},
			wantIDs: []string{},
		},
		{
			name: "target group lookup error skips that LB (continue)",
			mock: &mockELBv2{
				lbPages: [][]elbtypes.LoadBalancer{{
					{LoadBalancerArn: awssdk.String("arn:lb/1"), LoadBalancerName: awssdk.String("err-lb")},
				}},
				tgErrForLBARN: "arn:lb/1",
			},
			wantIDs: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{elbv2: tt.mock}
			got, err := p.orphanLoadBalancers(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotIDs := make([]string, 0, len(got))
			for _, o := range got {
				gotIDs = append(gotIDs, o.ID)
				if o.Kind != cloud.OrphanLoadBalancer {
					t.Errorf("kind: got %v", o.Kind)
				}
			}
			if !equalStrings(gotIDs, tt.wantIDs) {
				t.Errorf("ids: got %v, want %v", gotIDs, tt.wantIDs)
			}
		})
	}
}

// ── ListOrphans ───────────────────────────────────────────────────────────────

func TestListOrphans_AggregatesAllDomains(t *testing.T) {
	p := &Provider{
		ec2: &mockEC2{
			volumePages: [][]ec2types.Volume{{
				{VolumeId: awssdk.String("vol-1"), Size: awssdk.Int32(100)},
			}},
			addressesOut: []ec2types.Address{
				{AllocationId: awssdk.String("eipalloc-1"), PublicIp: awssdk.String("1.2.3.4")},
			},
		},
		elbv2: &mockELBv2{
			lbPages: [][]elbtypes.LoadBalancer{{
				{LoadBalancerArn: awssdk.String("arn:lb/1"), LoadBalancerName: awssdk.String("empty")},
			}},
		},
	}
	got, err := p.ListOrphans(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d orphans, want 3 (1 disk + 1 ip + 1 lb): %v", len(got), got)
	}
}

func TestListOrphans_AddressErrorBubblesUp(t *testing.T) {
	p := &Provider{
		ec2:   &mockEC2{addressesErr: errors.New("creds expired")},
		elbv2: &mockELBv2{},
	}
	_, err := p.ListOrphans(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

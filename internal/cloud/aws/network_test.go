package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stxkxs/matlock/internal/cloud"
)

// networkMockEC2 extends mockEC2 with security-group support.
type networkMockEC2 struct {
	mockEC2
	sgPages [][]ec2types.SecurityGroup
	sgErr   error
	sgCalls int
}

func (m *networkMockEC2) DescribeSecurityGroups(_ context.Context, _ *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if m.sgErr != nil {
		return nil, m.sgErr
	}
	idx := m.sgCalls
	m.sgCalls++
	if idx >= len(m.sgPages) {
		return &ec2.DescribeSecurityGroupsOutput{}, nil
	}
	var token *string
	if idx+1 < len(m.sgPages) {
		token = awssdk.String("next")
	}
	return &ec2.DescribeSecurityGroupsOutput{
		SecurityGroups: m.sgPages[idx],
		NextToken:      token,
	}, nil
}

func makeSG(id string, ingress, egress []ec2types.IpPermission) ec2types.SecurityGroup {
	return ec2types.SecurityGroup{
		GroupId:             awssdk.String(id),
		IpPermissions:       ingress,
		IpPermissionsEgress: egress,
	}
}

func tcpPort(port int32, cidr string) ec2types.IpPermission {
	return ec2types.IpPermission{
		IpProtocol: awssdk.String("tcp"),
		FromPort:   awssdk.Int32(port),
		ToPort:     awssdk.Int32(port),
		IpRanges:   []ec2types.IpRange{{CidrIp: awssdk.String(cidr)}},
	}
}

func TestAuditNetwork(t *testing.T) {
	tests := []struct {
		name      string
		sgs       []ec2types.SecurityGroup
		wantSev   []cloud.Severity
		wantTypes []cloud.NetworkFindingType
	}{
		{
			name:      "SSH open to internet is critical",
			sgs:       []ec2types.SecurityGroup{makeSG("sg-1", []ec2types.IpPermission{tcpPort(22, "0.0.0.0/0")}, nil)},
			wantSev:   []cloud.Severity{cloud.SeverityCritical},
			wantTypes: []cloud.NetworkFindingType{cloud.NetworkAdminPortOpen},
		},
		{
			name: "all-traffic ingress is critical",
			sgs: []ec2types.SecurityGroup{makeSG("sg-1", []ec2types.IpPermission{{
				IpProtocol: awssdk.String("-1"),
				IpRanges:   []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}},
			}}, nil)},
			wantSev:   []cloud.Severity{cloud.SeverityCritical},
			wantTypes: []cloud.NetworkFindingType{cloud.NetworkAdminPortOpen},
		},
		{
			name: "HTTP on 80 is expected and skipped",
			sgs:  []ec2types.SecurityGroup{makeSG("sg-1", []ec2types.IpPermission{tcpPort(80, "0.0.0.0/0")}, nil)},
		},
		{
			name: "HTTPS on 443 is expected and skipped",
			sgs:  []ec2types.SecurityGroup{makeSG("sg-1", []ec2types.IpPermission{tcpPort(443, "0.0.0.0/0")}, nil)},
		},
		{
			name:      "RDP open to internet is critical",
			sgs:       []ec2types.SecurityGroup{makeSG("sg-1", []ec2types.IpPermission{tcpPort(3389, "0.0.0.0/0")}, nil)},
			wantSev:   []cloud.Severity{cloud.SeverityCritical},
			wantTypes: []cloud.NetworkFindingType{cloud.NetworkAdminPortOpen},
		},
		{
			name:      "open port 8080 to internet is high (non-sensitive)",
			sgs:       []ec2types.SecurityGroup{makeSG("sg-1", []ec2types.IpPermission{tcpPort(8080, "0.0.0.0/0")}, nil)},
			wantSev:   []cloud.Severity{cloud.SeverityHigh},
			wantTypes: []cloud.NetworkFindingType{cloud.NetworkOpenIngress},
		},
		{
			name: "IPv6 ::/0 also detected",
			sgs: []ec2types.SecurityGroup{makeSG("sg-1", []ec2types.IpPermission{{
				IpProtocol: awssdk.String("tcp"),
				FromPort:   awssdk.Int32(22), ToPort: awssdk.Int32(22),
				Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: awssdk.String("::/0")}},
			}}, nil)},
			wantSev:   []cloud.Severity{cloud.SeverityCritical},
			wantTypes: []cloud.NetworkFindingType{cloud.NetworkAdminPortOpen},
		},
		{
			name: "private CIDR is NOT flagged",
			sgs:  []ec2types.SecurityGroup{makeSG("sg-1", []ec2types.IpPermission{tcpPort(22, "10.0.0.0/8")}, nil)},
		},
		{
			name: "unrestricted egress is medium",
			sgs: []ec2types.SecurityGroup{makeSG("sg-1", nil, []ec2types.IpPermission{{
				IpProtocol: awssdk.String("-1"),
				IpRanges:   []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}},
			}})},
			wantSev:   []cloud.Severity{cloud.SeverityMedium},
			wantTypes: []cloud.NetworkFindingType{cloud.NetworkOpenEgress},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{ec2: &networkMockEC2{sgPages: [][]ec2types.SecurityGroup{tt.sgs}}}
			got, err := p.AuditNetwork(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.wantSev) {
				t.Fatalf("findings: got %d, want %d (%v)", len(got), len(tt.wantSev), got)
			}
			for i := range got {
				if got[i].Severity != tt.wantSev[i] {
					t.Errorf("finding[%d] severity: got %v, want %v", i, got[i].Severity, tt.wantSev[i])
				}
				if got[i].Type != tt.wantTypes[i] {
					t.Errorf("finding[%d] type: got %v, want %v", i, got[i].Type, tt.wantTypes[i])
				}
			}
		})
	}
}

func TestAuditNetwork_PaginatorErrorIsFatal(t *testing.T) {
	p := &Provider{ec2: &networkMockEC2{sgErr: errors.New("throttled")}}
	_, err := p.AuditNetwork(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPortInRange(t *testing.T) {
	tests := []struct {
		port, from, to int
		want           bool
	}{
		{22, 22, 22, true},
		{22, 20, 30, true},
		{22, 23, 80, false},
		{22, 0, 0, false}, // both zero means rule was empty
	}
	for _, tt := range tests {
		t.Run("portInRange", func(t *testing.T) {
			got := portInRange(tt.port, tt.from, tt.to)
			if got != tt.want {
				t.Errorf("port=%d from=%d to=%d: got %v, want %v", tt.port, tt.from, tt.to, got, tt.want)
			}
		})
	}
}

func TestPortStr(t *testing.T) {
	tests := []struct {
		from, to int
		want     string
	}{
		{22, 22, "22"},
		{20, 30, "20-30"},
	}
	for _, tt := range tests {
		got := portStr(tt.from, tt.to)
		if got != tt.want {
			t.Errorf("from=%d to=%d: got %q, want %q", tt.from, tt.to, got, tt.want)
		}
	}
}

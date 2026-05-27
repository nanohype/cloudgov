package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/stxkxs/matlock/internal/cloud"
)

type mockNSG struct {
	nsgs []*armnetwork.SecurityGroup
	nsg  *armnetwork.SecurityGroup
	err  error
}

func (m *mockNSG) ListAll(_ context.Context) ([]*armnetwork.SecurityGroup, error) {
	return m.nsgs, m.err
}
func (m *mockNSG) Get(_ context.Context, _, _ string) (*armnetwork.SecurityGroup, error) {
	if m.nsg == nil {
		return nil, errors.New("not found")
	}
	return m.nsg, nil
}

func makeNSG(name string, rules []*armnetwork.SecurityRule) *armnetwork.SecurityGroup {
	return &armnetwork.SecurityGroup{
		Name:     to.Ptr(name),
		Location: to.Ptr("eastus"),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: rules,
		},
	}
}

func tcpAllow(port string) *armnetwork.SecurityRule {
	access := armnetwork.SecurityRuleAccessAllow
	dir := armnetwork.SecurityRuleDirectionInbound
	proto := armnetwork.SecurityRuleProtocolTCP
	return &armnetwork.SecurityRule{
		Name: to.Ptr("rule"),
		Properties: &armnetwork.SecurityRulePropertiesFormat{
			Access:                   &access,
			Direction:                &dir,
			Protocol:                 &proto,
			SourceAddressPrefix:      to.Ptr("*"),
			DestinationPortRange:     to.Ptr(port),
			DestinationAddressPrefix: to.Ptr("*"),
		},
	}
}

func TestAuditNetwork_SSHOpen(t *testing.T) {
	p := &Provider{nsgs: &mockNSG{nsgs: []*armnetwork.SecurityGroup{
		makeNSG("nsg-1", []*armnetwork.SecurityRule{tcpAllow("22")}),
	}}}
	got, err := p.AuditNetwork(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Severity != cloud.SeverityCritical {
		t.Errorf("expected critical, got %v", got)
	}
}

func TestAuditNetwork_HTTPSkipped(t *testing.T) {
	p := &Provider{nsgs: &mockNSG{nsgs: []*armnetwork.SecurityGroup{
		makeNSG("nsg-1", []*armnetwork.SecurityRule{tcpAllow("80")}),
	}}}
	got, _ := p.AuditNetwork(context.Background())
	if len(got) != 0 {
		t.Errorf("port 80 should be skipped, got %v", got)
	}
}

func TestAuditNetwork_AllInbound(t *testing.T) {
	p := &Provider{nsgs: &mockNSG{nsgs: []*armnetwork.SecurityGroup{
		makeNSG("nsg-1", []*armnetwork.SecurityRule{tcpAllow("*")}),
	}}}
	got, _ := p.AuditNetwork(context.Background())
	if len(got) != 1 || got[0].Severity != cloud.SeverityCritical {
		t.Errorf("expected critical, got %v", got)
	}
}

func TestAuditNetwork_Error(t *testing.T) {
	p := &Provider{nsgs: &mockNSG{err: errors.New("api")}}
	_, err := p.AuditNetwork(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPortInNSGRange(t *testing.T) {
	if !portInNSGRange(22, "22") {
		t.Error("22 should be in 22")
	}
	if !portInNSGRange(22, "20-30") {
		t.Error("22 should be in 20-30")
	}
	if portInNSGRange(22, "80") {
		t.Error("22 should NOT be in 80")
	}
	if !portInNSGRange(22, "*") {
		t.Error("* should match any port")
	}
}

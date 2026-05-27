package azure

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"

	"github.com/stxkxs/matlock/internal/cloud"
)

func TestListResources(t *testing.T) {
	p := &Provider{subscriptionID: "sub-1", resources: &mockResources{
		resources: []*armresources.GenericResourceExpanded{
			{
				ID:       to.Ptr("/r/1"),
				Name:     to.Ptr("vm-1"),
				Type:     to.Ptr("Microsoft.Compute/virtualMachines"),
				Location: to.Ptr("eastus"),
				Tags:     map[string]*string{"env": to.Ptr("prod")},
			},
			{
				ID:       to.Ptr("/r/2"),
				Name:     to.Ptr("sa-1"),
				Type:     to.Ptr("Microsoft.Storage/storageAccounts"),
				Location: to.Ptr("eastus"),
			},
		},
	}}
	got, err := p.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 resources, got %d", len(got))
	}
	byType := map[string]cloud.ResourceKind{}
	for _, r := range got {
		byType[r.Type] = r.Kind
	}
	if byType["compute:virtualMachines"] != cloud.ResourceCompute {
		t.Errorf("VM kind: got %v", byType["compute:virtualMachines"])
	}
	if byType["storage:storageAccounts"] != cloud.ResourceStorage {
		t.Errorf("storage kind: got %v", byType["storage:storageAccounts"])
	}
}

func TestListResources_NoSubscription(t *testing.T) {
	p := &Provider{}
	_, err := p.ListResources(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNormalizeAzureType(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Microsoft.Compute/virtualMachines", "compute:virtualMachines"},
		{"Microsoft.Storage/storageAccounts", "storage:storageAccounts"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		got := normalizeAzureType(tt.in)
		if got != tt.want {
			t.Errorf("%q: got %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestAzureResourceKind(t *testing.T) {
	tests := []struct {
		in   string
		want cloud.ResourceKind
	}{
		{"Microsoft.Compute/virtualMachines", cloud.ResourceCompute},
		{"Microsoft.Storage/storageAccounts", cloud.ResourceStorage},
		{"Microsoft.Sql/servers", cloud.ResourceDatabase},
		{"Microsoft.Network/virtualNetworks", cloud.ResourceNetwork},
		{"Microsoft.Network/loadBalancers", cloud.ResourceLoadBalancer},
		{"Microsoft.ContainerService/managedClusters", cloud.ResourceContainer},
		{"Microsoft.Web/sites", cloud.ResourceServerless},
		{"Microsoft.Network/dnsZones", cloud.ResourceDNS},
		{"Microsoft.Cdn/profiles", cloud.ResourceCDN},
		{"Microsoft.Cache/redis", cloud.ResourceDatabase},
		{"Microsoft.Unknown/foo", cloud.ResourceOther},
	}
	for _, tt := range tests {
		got := azureResourceKind(tt.in)
		if got != tt.want {
			t.Errorf("%q: got %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestDerefStr(t *testing.T) {
	s := "hello"
	if derefStr(&s) != "hello" || derefStr(nil) != "" {
		t.Error("derefStr broken")
	}
}

func TestAzureTagsToMap(t *testing.T) {
	got := azureTagsToMap(map[string]*string{"k1": to.Ptr("v1"), "k2": nil})
	if got["k1"] != "v1" {
		t.Errorf("k1: got %q", got["k1"])
	}
	if _, ok := got["k2"]; ok {
		t.Error("k2 with nil value should be skipped")
	}
	if azureTagsToMap(nil) != nil {
		t.Error("nil input should return nil")
	}
}

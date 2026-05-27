package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

type mockResources struct {
	resources []*armresources.GenericResourceExpanded
	err       error
}

func (m *mockResources) List(_ context.Context) ([]*armresources.GenericResourceExpanded, error) {
	return m.resources, m.err
}

func TestAuditTags_NoRequired(t *testing.T) {
	p := &Provider{}
	got, err := p.AuditTags(context.Background(), nil)
	if err != nil || got != nil {
		t.Errorf("expected (nil, nil), got (%v, %v)", got, err)
	}
}

func TestAuditTags_MissingTag(t *testing.T) {
	p := &Provider{resources: &mockResources{resources: []*armresources.GenericResourceExpanded{
		{
			ID: to.Ptr("/sub/r/1"), Name: to.Ptr("vm-1"),
			Type: to.Ptr("Microsoft.Compute/virtualMachines"), Location: to.Ptr("eastus"),
			Tags: map[string]*string{"env": to.Ptr("prod")},
		},
	}}}
	got, err := p.AuditTags(context.Background(), []string{"env", "owner"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].MissingTags[0] != "owner" {
		t.Errorf("expected missing=owner, got %v", got)
	}
}

func TestAuditTags_AllPresent(t *testing.T) {
	p := &Provider{resources: &mockResources{resources: []*armresources.GenericResourceExpanded{
		{
			ID: to.Ptr("/sub/r/1"), Name: to.Ptr("vm-1"),
			Tags: map[string]*string{"env": to.Ptr("prod"), "owner": to.Ptr("team")},
		},
	}}}
	got, _ := p.AuditTags(context.Background(), []string{"env", "owner"})
	if len(got) != 0 {
		t.Errorf("expected no findings, got %v", got)
	}
}

func TestAuditTags_Error(t *testing.T) {
	p := &Provider{resources: &mockResources{err: errors.New("api")}}
	_, err := p.AuditTags(context.Background(), []string{"env"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAzureMissingTags(t *testing.T) {
	have := map[string]struct{}{"env": {}}
	got := azureMissingTags([]string{"env", "owner"}, have)
	if len(got) != 1 || got[0] != "owner" {
		t.Errorf("got %v", got)
	}
}

package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
)

const fakeAWSKey = "AKIAIOSFODNN7EXAMPLE"

type mockWebApps struct {
	apps     []*armappservice.Site
	settings map[string]map[string]*string // name -> settings
	listErr  error
	getErr   error
}

func (m *mockWebApps) List(_ context.Context) ([]*armappservice.Site, error) {
	return m.apps, m.listErr
}
func (m *mockWebApps) ListApplicationSettings(_ context.Context, _, name string) (map[string]*string, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.settings[name], nil
}

func TestScanSecrets_WebApp(t *testing.T) {
	p := &Provider{webApps: &mockWebApps{
		apps: []*armappservice.Site{
			{
				ID:       to.Ptr("/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.Web/sites/app-1"),
				Name:     to.Ptr("app-1"),
				Location: to.Ptr("eastus"),
			},
		},
		settings: map[string]map[string]*string{
			"app-1": {"AWS_KEY": to.Ptr(fakeAWSKey)},
		},
	}}
	got, err := p.ScanSecrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 || got[0].ResourceType != "app_service_setting" {
		t.Errorf("expected app_service_setting finding, got %v", got)
	}
}

func TestScanSecrets_FunctionApp(t *testing.T) {
	p := &Provider{webApps: &mockWebApps{
		apps: []*armappservice.Site{
			{
				ID:       to.Ptr("/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.Web/sites/fn-1"),
				Name:     to.Ptr("fn-1"),
				Kind:     to.Ptr("functionapp"),
				Location: to.Ptr("eastus"),
			},
		},
		settings: map[string]map[string]*string{
			"fn-1": {"TOKEN": to.Ptr(fakeAWSKey)},
		},
	}}
	got, _ := p.ScanSecrets(context.Background())
	if len(got) == 0 || got[0].ResourceType != "function_app_setting" {
		t.Errorf("expected function_app_setting finding, got %v", got)
	}
}

func TestScanSecrets_ListError(t *testing.T) {
	p := &Provider{webApps: &mockWebApps{listErr: errors.New("auth")}}
	_, err := p.ScanSecrets(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResourceGroupFromID(t *testing.T) {
	id := to.Ptr("/subscriptions/s/resourceGroups/my-rg/providers/Microsoft.Web/sites/app")
	if got := resourceGroupFromID(id); got != "my-rg" {
		t.Errorf("got %q, want my-rg", got)
	}
	if got := resourceGroupFromID(nil); got != "" {
		t.Errorf("nil should return empty, got %q", got)
	}
	if got := resourceGroupFromID(to.Ptr("not-an-arm-id")); got != "" {
		t.Errorf("invalid should return empty, got %q", got)
	}
}

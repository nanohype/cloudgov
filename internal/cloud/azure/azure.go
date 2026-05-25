package azure

import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Provider implements Matlock provider interfaces for Azure.
type Provider struct {
	subscriptionID string
	cred           *azidentity.DefaultAzureCredential
}

// New creates an Azure provider using DefaultAzureCredential.
func New(ctx context.Context, subscriptionID string) (*Provider, error) {
	if subscriptionID == "" {
		subscriptionID = os.Getenv("AZURE_SUBSCRIPTION_ID")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure default credential: %w", err)
	}
	return &Provider{
		subscriptionID: subscriptionID,
		cred:           cred,
	}, nil
}

// Name returns the provider identifier.
func (p *Provider) Name() string { return "azure" }

// Detect returns true when Azure credentials are available.
func (p *Provider) Detect(_ context.Context) bool {
	envKeys := []string{
		"AZURE_CLIENT_ID",
		"AZURE_TENANT_ID",
		"AZURE_CLIENT_SECRET",
		"AZURE_CLIENT_CERTIFICATE_PATH",
		"AZURE_SUBSCRIPTION_ID",
	}
	for _, k := range envKeys {
		if os.Getenv(k) != "" {
			return true
		}
	}
	// Check for Azure CLI login token cache
	home, _ := os.UserHomeDir()
	if home != "" {
		if _, err := os.Stat(home + "/.azure/accessTokens.json"); err == nil {
			return true
		}
		if _, err := os.Stat(home + "/.azure/msal_token_cache.json"); err == nil {
			return true
		}
	}
	return false
}

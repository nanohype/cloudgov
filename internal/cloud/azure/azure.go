package azure

import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/costmanagement/armcostmanagement"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
)

// Provider implements Matlock provider interfaces for Azure.
//
// Per-domain SDK clients are wrapped behind narrow adapter interfaces declared
// in the file that first uses them (roleAssignmentsAPI in rbac.go, etc.).
// Production wires the adapters in New(); tests construct Provider directly
// with hand-written mocks.
type Provider struct {
	subscriptionID  string
	cred            *azidentity.DefaultAzureCredential
	roleAssignments roleAssignmentsAPI
	roleDefinitions roleDefinitionsAPI
	activityLogs    activityLogsAPI
	disks           disksAPI
	publicIPs       publicIPsAPI
	nsgs            nsgAPI
	storageAccounts storageAccountsAPI
	keyVaults       keyVaultsAPI
	resources       resourcesAPI
	costQuery       costQueryAPI
	webApps         webAppsAPI
	computeUsage    computeUsageAPI
	networkUsage    networkUsageAPI
	vms             vmsAPI
	// newKeyVaultCertificates builds a per-vault certificates client.
	newKeyVaultCertificates func(vaultURI string) (keyVaultCertificatesAPI, error)
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
	p := &Provider{
		subscriptionID: subscriptionID,
		cred:           cred,
	}

	raClient, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("role assignments client: %w", err)
	}
	p.roleAssignments = &roleAssignmentsAdapter{client: raClient}

	rdClient, err := armauthorization.NewRoleDefinitionsClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("role definitions client: %w", err)
	}
	p.roleDefinitions = &roleDefinitionsAdapter{client: rdClient}

	alClient, err := armmonitor.NewActivityLogsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("activity logs client: %w", err)
	}
	p.activityLogs = &activityLogsAdapter{client: alClient}

	disksClient, err := armcompute.NewDisksClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("disks client: %w", err)
	}
	p.disks = &disksAdapter{client: disksClient}

	ipClient, err := armnetwork.NewPublicIPAddressesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("public IPs client: %w", err)
	}
	p.publicIPs = &publicIPsAdapter{client: ipClient}

	nsgClient, err := armnetwork.NewSecurityGroupsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("nsg client: %w", err)
	}
	p.nsgs = &nsgAdapter{client: nsgClient}

	saClient, err := armstorage.NewAccountsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("storage accounts client: %w", err)
	}
	p.storageAccounts = &storageAccountsAdapter{client: saClient}

	kvClient, err := armkeyvault.NewVaultsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("keyvault vaults client: %w", err)
	}
	p.keyVaults = &keyVaultsAdapter{client: kvClient}

	resClient, err := armresources.NewClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("resources client: %w", err)
	}
	p.resources = &resourcesAdapter{client: resClient}

	costClient, err := armcostmanagement.NewQueryClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("cost management client: %w", err)
	}
	p.costQuery = &costQueryAdapter{client: costClient}

	webClient, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("web apps client: %w", err)
	}
	p.webApps = &webAppsAdapter{client: webClient}

	cuClient, err := armcompute.NewUsageClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("compute usage client: %w", err)
	}
	p.computeUsage = &computeUsageAdapter{client: cuClient}

	nuClient, err := armnetwork.NewUsagesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("network usage client: %w", err)
	}
	p.networkUsage = &networkUsageAdapter{client: nuClient}

	vmClient, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("vms client: %w", err)
	}
	p.vms = &vmsAdapter{client: vmClient}

	p.newKeyVaultCertificates = func(vaultURI string) (keyVaultCertificatesAPI, error) {
		c, err := azcertificates.NewClient(vaultURI, cred, nil)
		if err != nil {
			return nil, err
		}
		return &keyVaultCertificatesAdapter{client: c}, nil
	}

	return p, nil
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

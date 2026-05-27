package azure

import (
	"context"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/stxkxs/matlock/internal/cloud"
)

// keyVaultsAPI is the narrow Key Vault management surface used here.
type keyVaultsAPI interface {
	ListBySubscription(ctx context.Context) ([]*armkeyvault.Vault, error)
	Get(ctx context.Context, resourceGroup, name string) (*armkeyvault.Vault, error)
}

type keyVaultsAdapter struct{ client *armkeyvault.VaultsClient }

func (a *keyVaultsAdapter) ListBySubscription(ctx context.Context) ([]*armkeyvault.Vault, error) {
	var out []*armkeyvault.Vault
	pager := a.client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (a *keyVaultsAdapter) Get(ctx context.Context, rg, name string) (*armkeyvault.Vault, error) {
	resp, err := a.client.Get(ctx, rg, name, nil)
	if err != nil {
		return nil, err
	}
	return &resp.Vault, nil
}

// keyVaultCertificatesAPI is the narrow per-vault certificates surface used here.
type keyVaultCertificatesAPI interface {
	ListCertificateProperties(ctx context.Context) ([]*azcertificates.CertificateProperties, error)
}

type keyVaultCertificatesAdapter struct{ client *azcertificates.Client }

func (a *keyVaultCertificatesAdapter) ListCertificateProperties(ctx context.Context) ([]*azcertificates.CertificateProperties, error) {
	var out []*azcertificates.CertificateProperties
	pager := a.client.NewListCertificatePropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

// ListCertificates discovers Azure Key Vault certificates expiring within 180 days.
func (p *Provider) ListCertificates(ctx context.Context) ([]cloud.CertFinding, error) {
	vaults, err := p.keyVaults.ListBySubscription(ctx)
	if err != nil {
		return nil, fmt.Errorf("list key vaults: %w", err)
	}

	now := time.Now()
	var findings []cloud.CertFinding

	for _, vault := range vaults {
		if vault.Properties == nil || vault.Properties.VaultURI == nil {
			continue
		}
		vaultURI := *vault.Properties.VaultURI
		vaultName := ptrStr(vault.Name)
		region := ptrStr(vault.Location)

		certFindings, err := p.listVaultCerts(ctx, vaultURI, vaultName, region, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: key vault %s: %v\n", vaultName, err)
			continue
		}
		findings = append(findings, certFindings...)
	}
	return findings, nil
}

func (p *Provider) listVaultCerts(ctx context.Context, vaultURI, vaultName, region string, now time.Time) ([]cloud.CertFinding, error) {
	client, err := p.newKeyVaultCertificates(vaultURI)
	if err != nil {
		return nil, fmt.Errorf("certificates client: %w", err)
	}

	certs, err := client.ListCertificateProperties(ctx)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}

	var findings []cloud.CertFinding
	for _, cert := range certs {
		if cert == nil || cert.Attributes == nil || cert.Attributes.Expires == nil {
			continue
		}
		expiry := *cert.Attributes.Expires
		daysLeft := int(math.Floor(expiry.Sub(now).Hours() / 24))
		if daysLeft > 180 {
			continue
		}

		certName := certNameFromID(string(*cert.ID))
		sev, status := cloud.CertSeverity(daysLeft)
		findings = append(findings, cloud.CertFinding{
			Severity:  sev,
			Status:    status,
			Provider:  "azure",
			Domain:    certName,
			ARN:       fmt.Sprintf("%s/certificates/%s", vaultName, certName),
			Region:    region,
			ExpiresAt: expiry,
			DaysLeft:  daysLeft,
			Detail:    fmt.Sprintf("certificate %s in vault %s expires in %d days", certName, vaultName, daysLeft),
		})
	}
	return findings, nil
}

// certNameFromID extracts the certificate name from a Key Vault certificate ID URL.
// ID format: https://{vault}.vault.azure.net/certificates/{name}/{version}
func certNameFromID(id string) string {
	// Find "certificates/" segment
	const marker = "/certificates/"
	idx := -1
	for i := 0; i+len(marker) <= len(id); i++ {
		if id[i:i+len(marker)] == marker {
			idx = i + len(marker)
			break
		}
	}
	if idx < 0 {
		return id
	}
	rest := id[idx:]
	// Take everything up to the next slash (version)
	for i, c := range rest {
		if c == '/' {
			return rest[:i]
		}
	}
	return rest
}

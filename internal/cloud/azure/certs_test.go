package azure

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
)

type mockKeyVaults struct {
	vaults []*armkeyvault.Vault
	vault  *armkeyvault.Vault
	err    error
}

func (m *mockKeyVaults) ListBySubscription(_ context.Context) ([]*armkeyvault.Vault, error) {
	return m.vaults, m.err
}
func (m *mockKeyVaults) Get(_ context.Context, _, _ string) (*armkeyvault.Vault, error) {
	if m.vault == nil {
		return nil, errors.New("not found")
	}
	return m.vault, nil
}

type mockKeyVaultCerts struct {
	certs []*azcertificates.CertificateProperties
	err   error
}

func (m *mockKeyVaultCerts) ListCertificateProperties(_ context.Context) ([]*azcertificates.CertificateProperties, error) {
	return m.certs, m.err
}

func TestListCertificates(t *testing.T) {
	now := time.Now()
	expSoon := now.Add(7 * 24 * time.Hour)
	expFar := now.Add(365 * 24 * time.Hour)
	certs := []*azcertificates.CertificateProperties{
		{ID: to.Ptr(azcertificates.ID("https://v.vault.azure.net/certificates/soon/abc")),
			Attributes: &azcertificates.CertificateAttributes{Expires: &expSoon}},
		{ID: to.Ptr(azcertificates.ID("https://v.vault.azure.net/certificates/far/abc")),
			Attributes: &azcertificates.CertificateAttributes{Expires: &expFar}}, // skipped
	}

	p := &Provider{
		keyVaults: &mockKeyVaults{vaults: []*armkeyvault.Vault{
			{Name: to.Ptr("v1"), Location: to.Ptr("eastus"),
				Properties: &armkeyvault.VaultProperties{VaultURI: to.Ptr("https://v1.vault.azure.net/")}},
		}},
		newKeyVaultCertificates: func(_ string) (keyVaultCertificatesAPI, error) {
			return &mockKeyVaultCerts{certs: certs}, nil
		},
	}

	got, err := p.ListCertificates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 finding (within 180-day window), got %d", len(got))
	}
}

func TestListCertificates_VaultFailureSkipped(t *testing.T) {
	p := &Provider{
		keyVaults: &mockKeyVaults{vaults: []*armkeyvault.Vault{
			{Name: to.Ptr("bad"), Properties: &armkeyvault.VaultProperties{VaultURI: to.Ptr("https://bad.vault.azure.net/")}},
		}},
		newKeyVaultCertificates: func(_ string) (keyVaultCertificatesAPI, error) {
			return nil, errors.New("network")
		},
	}
	got, err := p.ListCertificates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 findings when vault unreachable, got %d", len(got))
	}
}

func TestCertNameFromID(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://v.vault.azure.net/certificates/mycert/abc123", "mycert"},
		{"https://v.vault.azure.net/certificates/mycert", "mycert"},
		{"not-a-url", "not-a-url"},
	}
	for _, tt := range tests {
		got := certNameFromID(tt.in)
		if got != tt.want {
			t.Errorf("%q: got %q, want %q", tt.in, got, tt.want)
		}
	}
}

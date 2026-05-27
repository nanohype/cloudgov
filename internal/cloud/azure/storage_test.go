package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/stxkxs/matlock/internal/cloud"
)

type mockStorageAccounts struct {
	accounts []*armstorage.Account
	props    *armstorage.Account
	err      error
	getErr   error
}

func (m *mockStorageAccounts) List(_ context.Context) ([]*armstorage.Account, error) {
	return m.accounts, m.err
}
func (m *mockStorageAccounts) GetProperties(_ context.Context, _, _ string) (*armstorage.Account, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.props, nil
}

func TestAuditStorage_PublicAccess(t *testing.T) {
	p := &Provider{storageAccounts: &mockStorageAccounts{accounts: []*armstorage.Account{
		{Name: to.Ptr("public"), Location: to.Ptr("eastus"),
			Properties: &armstorage.AccountProperties{
				AllowBlobPublicAccess:  to.Ptr(true),
				Encryption:             &armstorage.Encryption{},
				EnableHTTPSTrafficOnly: to.Ptr(true),
			}},
	}}}
	got, err := p.AuditStorage(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Severity != cloud.SeverityCritical || got[0].Type != cloud.BucketPublicAccess {
		t.Errorf("expected critical public-access finding, got %v", got)
	}
}

func TestAuditStorage_NoEncryption(t *testing.T) {
	p := &Provider{storageAccounts: &mockStorageAccounts{accounts: []*armstorage.Account{
		{Name: to.Ptr("noenc"), Location: to.Ptr("eastus"),
			Properties: &armstorage.AccountProperties{
				AllowBlobPublicAccess:  to.Ptr(false),
				Encryption:             nil,
				EnableHTTPSTrafficOnly: to.Ptr(true),
			}},
	}}}
	got, _ := p.AuditStorage(context.Background())
	if len(got) != 1 || got[0].Type != cloud.BucketUnencrypted {
		t.Errorf("expected unencrypted finding, got %v", got)
	}
}

func TestAuditStorage_NoHTTPS(t *testing.T) {
	p := &Provider{storageAccounts: &mockStorageAccounts{accounts: []*armstorage.Account{
		{Name: to.Ptr("http"), Location: to.Ptr("eastus"),
			Properties: &armstorage.AccountProperties{
				AllowBlobPublicAccess:  to.Ptr(false),
				Encryption:             &armstorage.Encryption{},
				EnableHTTPSTrafficOnly: to.Ptr(false),
			}},
	}}}
	got, _ := p.AuditStorage(context.Background())
	if len(got) != 1 || got[0].Severity != cloud.SeverityHigh {
		t.Errorf("expected HTTPS finding, got %v", got)
	}
}

func TestAuditStorage_ListError(t *testing.T) {
	p := &Provider{storageAccounts: &mockStorageAccounts{err: errors.New("auth")}}
	_, err := p.AuditStorage(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

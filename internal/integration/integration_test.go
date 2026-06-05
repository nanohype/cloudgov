package integration

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nanohype/cloudgov/internal/certs"
	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/network"
	orphanscanner "github.com/nanohype/cloudgov/internal/orphans"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/providers"
	"github.com/nanohype/cloudgov/internal/secrets"
	"github.com/nanohype/cloudgov/internal/storage"
	"github.com/nanohype/cloudgov/internal/tags"
)

// fixtureProvider is a cloud.Provider implementing every finding-domain capability
// with canned data, so the registry can resolve it by capability.
type fixtureProvider struct {
	orphans []cloud.OrphanResource
	buckets []cloud.BucketFinding
	network []cloud.NetworkFinding
	certs   []cloud.CertFinding
	tags    []cloud.TagFinding
	secrets []cloud.SecretFinding
}

func (fixtureProvider) Name() string                { return "fixture" }
func (fixtureProvider) Detect(context.Context) bool { return true }

func (f fixtureProvider) ListOrphans(context.Context) ([]cloud.OrphanResource, error) {
	return f.orphans, nil
}
func (f fixtureProvider) AuditStorage(context.Context) ([]cloud.BucketFinding, error) {
	return f.buckets, nil
}
func (f fixtureProvider) AuditNetwork(context.Context) ([]cloud.NetworkFinding, error) {
	return f.network, nil
}
func (f fixtureProvider) ListCertificates(context.Context) ([]cloud.CertFinding, error) {
	return f.certs, nil
}
func (f fixtureProvider) AuditTags(context.Context, []string) ([]cloud.TagFinding, error) {
	return f.tags, nil
}
func (f fixtureProvider) ScanSecrets(context.Context) ([]cloud.SecretFinding, error) {
	return f.secrets, nil
}

// fixtureFactory adapts a fixtureProvider to providers.Factory so it can be
// resolved through the real registry.
type fixtureFactory struct{ p cloud.Provider }

func (fixtureFactory) Name() string                { return "fixture" }
func (fixtureFactory) Detect(context.Context) bool { return true }
func (f fixtureFactory) New(context.Context) (cloud.Provider, error) {
	return f.p, nil
}

func registryFor(p cloud.Provider) *providers.Registry {
	return providers.NewRegistry(fixtureFactory{p: p})
}

// assertRendered checks that the JSON and table renderers both surface every
// marker — an identity field plus at least one more rendered field per domain, so
// a renderer that drops a field (not just the keyed one) is caught (json renderers
// return an error; table renderers don't).
func assertRendered(t *testing.T, renderJSON func(*bytes.Buffer) error, renderTable func(*bytes.Buffer), markers ...string) {
	t.Helper()
	var js bytes.Buffer
	if err := renderJSON(&js); err != nil {
		t.Fatalf("json render: %v", err)
	}
	var tbl bytes.Buffer
	renderTable(&tbl)
	for _, m := range markers {
		if !strings.Contains(js.String(), m) {
			t.Errorf("json output missing %q:\n%s", m, js.String())
		}
		if !strings.Contains(tbl.String(), m) {
			t.Errorf("table output missing %q:\n%s", m, tbl.String())
		}
	}
}

func TestIntegration_Orphans(t *testing.T) {
	fix := fixtureProvider{orphans: []cloud.OrphanResource{
		{Kind: cloud.OrphanDisk, ID: "vol-int", Name: "vol-int", Region: "us-west-2", Provider: "aws", MonthlyCost: 8, Detail: "available"},
	}}
	provs, err := providers.Capable[cloud.OrphansProvider](context.Background(), registryFor(fix))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got, err := orphanscanner.Scan(context.Background(), provs, orphanscanner.ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 1 || got[0].ID != "vol-int" {
		t.Fatalf("scan result: %+v", got)
	}
	assertRendered(t,
		func(b *bytes.Buffer) error { return output.WriteOrphans(b, got) },
		func(b *bytes.Buffer) { output.OrphanResources(b, got) },
		"vol-int", "available")
}

func TestIntegration_Storage(t *testing.T) {
	fix := fixtureProvider{buckets: []cloud.BucketFinding{
		{Severity: cloud.SeverityCritical, Type: cloud.BucketPublicAccess, Provider: "aws", Bucket: "leaky-int", Region: "us-east-1", Detail: "public"},
	}}
	provs, err := providers.Capable[cloud.StorageProvider](context.Background(), registryFor(fix))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got, err := storage.Scan(context.Background(), provs, storage.ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 1 || got[0].Bucket != "leaky-int" {
		t.Fatalf("scan result: %+v", got)
	}
	assertRendered(t,
		func(b *bytes.Buffer) error { return output.WriteStorage(b, got) },
		func(b *bytes.Buffer) { output.BucketFindings(b, got) },
		"leaky-int", "public")
}

func TestIntegration_Network(t *testing.T) {
	fix := fixtureProvider{network: []cloud.NetworkFinding{
		{Severity: cloud.SeverityHigh, Type: cloud.NetworkOpenIngress, Provider: "aws", Resource: "sg-int", Detail: "0.0.0.0/0 on 22"},
	}}
	provs, err := providers.Capable[cloud.NetworkProvider](context.Background(), registryFor(fix))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got, err := network.Scan(context.Background(), provs, network.ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 1 || got[0].Resource != "sg-int" {
		t.Fatalf("scan result: %+v", got)
	}
	assertRendered(t,
		func(b *bytes.Buffer) error { return output.WriteNetwork(b, got) },
		func(b *bytes.Buffer) { output.NetworkFindings(b, got) },
		"sg-int", "0.0.0.0/0")
}

func TestIntegration_Certs(t *testing.T) {
	fix := fixtureProvider{certs: []cloud.CertFinding{
		{Severity: cloud.SeverityCritical, Status: cloud.CertExpired, Provider: "aws", Domain: "int.example.com", ARN: "arn:int", ExpiresAt: time.Now(), DaysLeft: -1, Detail: "expired"},
	}}
	provs, err := providers.Capable[cloud.CertProvider](context.Background(), registryFor(fix))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got, err := certs.Scan(context.Background(), provs, certs.ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 1 || got[0].Domain != "int.example.com" {
		t.Fatalf("scan result: %+v", got)
	}
	assertRendered(t,
		func(b *bytes.Buffer) error { return output.WriteCerts(b, got) },
		func(b *bytes.Buffer) { output.CertFindings(b, got) },
		"int.example.com", "EXPIRED")
}

func TestIntegration_Tags(t *testing.T) {
	fix := fixtureProvider{tags: []cloud.TagFinding{
		{Severity: cloud.SeverityMedium, Provider: "aws", ResourceID: "i-int", ResourceType: "ec2:instance", Region: "us-west-2", MissingTags: []string{"owner"}, Detail: "missing owner"},
	}}
	provs, err := providers.Capable[cloud.TagProvider](context.Background(), registryFor(fix))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got, err := tags.Scan(context.Background(), provs, tags.ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "i-int" {
		t.Fatalf("scan result: %+v", got)
	}
	assertRendered(t,
		func(b *bytes.Buffer) error { return output.WriteTags(b, got) },
		func(b *bytes.Buffer) { output.TagFindings(b, got) },
		"i-int", "ec2:instance")
}

func TestIntegration_Secrets(t *testing.T) {
	fix := fixtureProvider{secrets: []cloud.SecretFinding{
		{Severity: cloud.SeverityHigh, Type: "aws_key", Provider: "aws", Resource: "lambda:int-fn", Key: "AWS_KEY", Match: "AKIA****", Detail: "leaked key"},
	}}
	provs, err := providers.Capable[cloud.SecretsProvider](context.Background(), registryFor(fix))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got, err := secrets.ScanProviders(context.Background(), provs, secrets.ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 1 || got[0].Resource != "lambda:int-fn" {
		t.Fatalf("scan result: %+v", got)
	}
	assertRendered(t,
		func(b *bytes.Buffer) error { return output.WriteSecrets(b, got) },
		func(b *bytes.Buffer) { output.SecretFindings(b, got) },
		"int-fn", "AKIA****")
}

// TestIntegration_SeverityFilterDiscriminates proves the scanner's MinSeverity is
// actually applied through the seam: a below-threshold finding is dropped, not just
// passed through. (The other tests use a zero-value threshold that admits everything.)
func TestIntegration_SeverityFilterDiscriminates(t *testing.T) {
	fix := fixtureProvider{buckets: []cloud.BucketFinding{
		{Severity: cloud.SeverityCritical, Type: cloud.BucketPublicAccess, Provider: "aws", Bucket: "crit-bkt"},
		{Severity: cloud.SeverityLow, Type: cloud.BucketNoLogging, Provider: "aws", Bucket: "low-bkt"},
	}}
	provs, err := providers.Capable[cloud.StorageProvider](context.Background(), registryFor(fix))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got, err := storage.Scan(context.Background(), provs, storage.ScanOptions{MinSeverity: cloud.SeverityHigh})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 1 || got[0].Bucket != "crit-bkt" {
		t.Fatalf("MinSeverity=HIGH should drop the LOW bucket; got %+v", got)
	}
}

// TestIntegration_NoProviderErrors confirms the resolve seam errors cleanly when no
// registered provider offers the requested capability.
func TestIntegration_NoProviderErrors(t *testing.T) {
	empty := providers.NewRegistry()
	if _, err := providers.Capable[cloud.OrphansProvider](context.Background(), empty); err == nil {
		t.Error("expected an error resolving from an empty registry")
	}
}

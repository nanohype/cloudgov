package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

type mockSecretsProvider struct {
	name     string
	findings []cloud.SecretFinding
	err      error
}

func (m *mockSecretsProvider) Name() string                  { return m.name }
func (m *mockSecretsProvider) Detect(_ context.Context) bool { return true }
func (m *mockSecretsProvider) ScanSecrets(_ context.Context) ([]cloud.SecretFinding, error) {
	return m.findings, m.err
}

func TestScanProviders(t *testing.T) {
	criticalFinding := cloud.SecretFinding{
		Severity: cloud.SeverityCritical, Type: cloud.SecretAWSAccessKey,
		Provider: "aws", Resource: "lambda:func-a",
	}
	highFinding := cloud.SecretFinding{
		Severity: cloud.SeverityHigh, Type: cloud.SecretPassword,
		Provider: "aws", Resource: "lambda:func-b",
	}
	mediumFinding := cloud.SecretFinding{
		Severity: cloud.SeverityMedium, Type: cloud.SecretGenericSecret,
		Provider: "gcp", Resource: "cloud-function:func-c",
	}

	tests := []struct {
		name          string
		providers     []cloud.SecretsProvider
		opts          ScanOptions
		wantResources []string
		wantErr       bool
	}{
		{
			name: "single provider returns sorted results",
			providers: []cloud.SecretsProvider{
				&mockSecretsProvider{name: "aws", findings: []cloud.SecretFinding{highFinding, criticalFinding}},
			},
			opts:          ScanOptions{},
			wantResources: []string{"lambda:func-a", "lambda:func-b"},
		},
		{
			name: "multiple providers merged and sorted by severity",
			providers: []cloud.SecretsProvider{
				&mockSecretsProvider{name: "aws", findings: []cloud.SecretFinding{highFinding}},
				&mockSecretsProvider{name: "gcp", findings: []cloud.SecretFinding{mediumFinding, criticalFinding}},
			},
			opts:          ScanOptions{},
			wantResources: []string{"lambda:func-a", "lambda:func-b", "cloud-function:func-c"},
		},
		{
			name: "severity filter excludes medium",
			providers: []cloud.SecretsProvider{
				&mockSecretsProvider{name: "aws", findings: []cloud.SecretFinding{criticalFinding, highFinding, mediumFinding}},
			},
			opts:          ScanOptions{MinSeverity: cloud.SeverityHigh},
			wantResources: []string{"lambda:func-a", "lambda:func-b"},
		},
		{
			name: "empty provider returns empty result",
			providers: []cloud.SecretsProvider{
				&mockSecretsProvider{name: "aws", findings: nil},
			},
			opts:          ScanOptions{},
			wantResources: []string{},
		},
		{
			name:          "no providers returns empty result",
			providers:     []cloud.SecretsProvider{},
			opts:          ScanOptions{},
			wantResources: []string{},
		},
		{
			name: "provider error is returned",
			providers: []cloud.SecretsProvider{
				&mockSecretsProvider{name: "aws", err: errors.New("credentials expired")},
			},
			opts:    ScanOptions{},
			wantErr: true,
		},
		{
			name: "error from second provider is returned",
			providers: []cloud.SecretsProvider{
				&mockSecretsProvider{name: "aws", findings: []cloud.SecretFinding{criticalFinding}},
				&mockSecretsProvider{name: "gcp", err: errors.New("quota exceeded")},
			},
			opts:    ScanOptions{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ScanProviders(context.Background(), tt.providers, tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(got) != len(tt.wantResources) {
				t.Fatalf("got %d findings, want %d", len(got), len(tt.wantResources))
			}
			for i, res := range tt.wantResources {
				if got[i].Resource != res {
					t.Errorf("finding[%d]: got Resource %q, want %q", i, got[i].Resource, res)
				}
			}

			for i := 1; i < len(got); i++ {
				ri := cloud.SeverityRank(got[i].Severity)
				rj := cloud.SeverityRank(got[i-1].Severity)
				if ri > rj {
					t.Errorf("findings not sorted by severity: [%d].Severity=%s > [%d].Severity=%s",
						i, got[i].Severity, i-1, got[i-1].Severity)
				}
			}
		})
	}
}

func TestScanProvidersErrorWrapsProviderName(t *testing.T) {
	provider := &mockSecretsProvider{name: "mycloud", err: errors.New("auth failed")}
	_, err := ScanProviders(context.Background(), []cloud.SecretsProvider{provider}, ScanOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	want := "mycloud: auth failed"
	if err.Error() != want {
		t.Errorf("error message: got %q, want %q", err.Error(), want)
	}
}

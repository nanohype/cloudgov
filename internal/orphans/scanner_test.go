package orphans

import (
	"context"
	"errors"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

type mockOrphansProvider struct {
	name    string
	orphans []cloud.OrphanResource
	err     error
}

func (m *mockOrphansProvider) Name() string                  { return m.name }
func (m *mockOrphansProvider) Detect(_ context.Context) bool { return true }
func (m *mockOrphansProvider) ListOrphans(_ context.Context) ([]cloud.OrphanResource, error) {
	return m.orphans, m.err
}

func TestScan(t *testing.T) {
	disk := cloud.OrphanResource{Kind: cloud.OrphanDisk, ID: "vol-1", Provider: "aws", MonthlyCost: 10.0}
	ip := cloud.OrphanResource{Kind: cloud.OrphanIP, ID: "eip-1", Provider: "aws", MonthlyCost: 3.6}
	lb := cloud.OrphanResource{Kind: cloud.OrphanLoadBalancer, ID: "lb-1", Provider: "gcp", MonthlyCost: 20.0}
	cheap := cloud.OrphanResource{Kind: cloud.OrphanSnapshot, ID: "snap-1", Provider: "aws", MonthlyCost: 0.5}

	tests := []struct {
		name      string
		providers []cloud.OrphansProvider
		opts      ScanOptions
		wantIDs   []string
		wantErr   bool
	}{
		{
			name: "single provider returns sorted results",
			providers: []cloud.OrphansProvider{
				&mockOrphansProvider{name: "aws", orphans: []cloud.OrphanResource{disk, ip}},
			},
			opts:    ScanOptions{},
			wantIDs: []string{"vol-1", "eip-1"},
		},
		{
			name: "multiple providers merged and sorted by cost descending",
			providers: []cloud.OrphansProvider{
				&mockOrphansProvider{name: "aws", orphans: []cloud.OrphanResource{disk, ip}},
				&mockOrphansProvider{name: "gcp", orphans: []cloud.OrphanResource{lb}},
			},
			opts:    ScanOptions{},
			wantIDs: []string{"lb-1", "vol-1", "eip-1"},
		},
		{
			name: "min cost filter excludes cheap resources",
			providers: []cloud.OrphansProvider{
				&mockOrphansProvider{name: "aws", orphans: []cloud.OrphanResource{disk, ip, cheap}},
			},
			opts:    ScanOptions{MinMonthlyCost: 5.0},
			wantIDs: []string{"vol-1"},
		},
		{
			name: "min cost filter at exact boundary includes resource",
			providers: []cloud.OrphansProvider{
				&mockOrphansProvider{name: "aws", orphans: []cloud.OrphanResource{disk, ip}},
			},
			opts:    ScanOptions{MinMonthlyCost: 3.6},
			wantIDs: []string{"vol-1", "eip-1"},
		},
		{
			name: "empty provider returns empty result",
			providers: []cloud.OrphansProvider{
				&mockOrphansProvider{name: "aws", orphans: nil},
			},
			opts:    ScanOptions{},
			wantIDs: []string{},
		},
		{
			name:      "no providers returns empty result",
			providers: []cloud.OrphansProvider{},
			opts:      ScanOptions{},
			wantIDs:   []string{},
		},
		{
			name: "provider error is returned",
			providers: []cloud.OrphansProvider{
				&mockOrphansProvider{name: "aws", err: errors.New("credentials expired")},
			},
			opts:    ScanOptions{},
			wantErr: true,
		},
		{
			name: "error from second provider is returned",
			providers: []cloud.OrphansProvider{
				&mockOrphansProvider{name: "aws", orphans: []cloud.OrphanResource{disk}},
				&mockOrphansProvider{name: "gcp", err: errors.New("quota exceeded")},
			},
			opts:    ScanOptions{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Scan(context.Background(), tt.providers, tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(got) != len(tt.wantIDs) {
				t.Fatalf("got %d orphans, want %d", len(got), len(tt.wantIDs))
			}
			for i, id := range tt.wantIDs {
				if got[i].ID != id {
					t.Errorf("orphan[%d]: got ID %q, want %q", i, got[i].ID, id)
				}
			}

			for i := 1; i < len(got); i++ {
				if got[i].MonthlyCost > got[i-1].MonthlyCost {
					t.Errorf("orphans not sorted: [%d].MonthlyCost=%f > [%d].MonthlyCost=%f",
						i, got[i].MonthlyCost, i-1, got[i-1].MonthlyCost)
				}
			}
		})
	}
}

func TestScanErrorWrapsProviderName(t *testing.T) {
	provider := &mockOrphansProvider{name: "mycloud", err: errors.New("auth failed")}
	_, err := Scan(context.Background(), []cloud.OrphansProvider{provider}, ScanOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	want := "mycloud: auth failed"
	if err.Error() != want {
		t.Errorf("error message: got %q, want %q", err.Error(), want)
	}
}

func TestTotalMonthlyCost(t *testing.T) {
	tests := []struct {
		name    string
		orphans []cloud.OrphanResource
		want    float64
	}{
		{
			name:    "nil slice returns zero",
			orphans: nil,
			want:    0,
		},
		{
			name:    "empty slice returns zero",
			orphans: []cloud.OrphanResource{},
			want:    0,
		},
		{
			name: "single orphan",
			orphans: []cloud.OrphanResource{
				{MonthlyCost: 10.5},
			},
			want: 10.5,
		},
		{
			name: "multiple orphans summed",
			orphans: []cloud.OrphanResource{
				{MonthlyCost: 10.0},
				{MonthlyCost: 3.6},
				{MonthlyCost: 20.0},
			},
			want: 33.6,
		},
		{
			name: "zero cost resources included in sum",
			orphans: []cloud.OrphanResource{
				{MonthlyCost: 5.0},
				{MonthlyCost: 0.0},
			},
			want: 5.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TotalMonthlyCost(tt.orphans)
			if got != tt.want {
				t.Errorf("TotalMonthlyCost() = %f, want %f", got, tt.want)
			}
		})
	}
}

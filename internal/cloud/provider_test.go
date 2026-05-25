package cloud

import "testing"

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		sev  Severity
		want int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{SeverityInfo, 0},
		{Severity("unknown"), 0},
	}
	for _, tt := range tests {
		t.Run(string(tt.sev), func(t *testing.T) {
			got := SeverityRank(tt.sev)
			if got != tt.want {
				t.Errorf("SeverityRank(%v): got %d, want %d", tt.sev, got, tt.want)
			}
		})
	}
}

func TestSeverityOrdering(t *testing.T) {
	// Critical > High > Medium > Low > Info
	if SeverityRank(SeverityCritical) <= SeverityRank(SeverityHigh) {
		t.Error("Critical should rank higher than High")
	}
	if SeverityRank(SeverityHigh) <= SeverityRank(SeverityMedium) {
		t.Error("High should rank higher than Medium")
	}
	if SeverityRank(SeverityMedium) <= SeverityRank(SeverityLow) {
		t.Error("Medium should rank higher than Low")
	}
	if SeverityRank(SeverityLow) <= SeverityRank(SeverityInfo) {
		t.Error("Low should rank higher than Info")
	}
}

func TestPrincipalTypeConstants(t *testing.T) {
	// Verify the canonical string values used across providers
	tests := []struct {
		pt   PrincipalType
		want string
	}{
		{PrincipalUser, "user"},
		{PrincipalRole, "role"},
		{PrincipalServiceAccount, "service_account"},
		{PrincipalManagedIdentity, "managed_identity"},
	}
	for _, tt := range tests {
		if string(tt.pt) != tt.want {
			t.Errorf("PrincipalType %v: got %q, want %q", tt.pt, string(tt.pt), tt.want)
		}
	}
}

func TestFindingTypeConstants(t *testing.T) {
	if string(FindingAdminAccess) == "" {
		t.Error("FindingAdminAccess should not be empty")
	}
	if string(FindingWildcardResource) == "" {
		t.Error("FindingWildcardResource should not be empty")
	}
}

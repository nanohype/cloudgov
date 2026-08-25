package cloud

import "testing"

func TestQuotaEffectiveSeverity(t *testing.T) {
	// Stored Severity wins, even when it disagrees with Utilization.
	stored := QuotaUsage{Utilization: 10, Severity: SeverityCritical}
	if got := stored.EffectiveSeverity(); got != SeverityCritical {
		t.Errorf("stored: got %q, want CRITICAL", got)
	}
	// Unset Severity falls back to computing from Utilization.
	for _, tc := range []struct {
		util float64
		want Severity
	}{
		{95, SeverityCritical},
		{85, SeverityHigh},
		{60, SeverityMedium},
		{10, SeverityLow},
	} {
		q := QuotaUsage{Utilization: tc.util}
		if got := q.EffectiveSeverity(); got != tc.want {
			t.Errorf("util %.0f: got %q, want %q", tc.util, got, tc.want)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		sev  Severity
		want int
	}{
		{SeverityCritical, 5},
		{SeverityHigh, 4},
		{SeverityMedium, 3},
		{SeverityLow, 2},
		{SeverityInfo, 1},
		// Rank 0 is reserved for a severity this tool does not recognise. Every
		// real level ranks above it, so a filter can never treat a typo as a
		// legitimate level — which is what INFO sharing rank 0 used to allow.
		{Severity("unknown"), 0},
		{Severity(""), 0},
	}
	for _, tt := range tests {
		t.Run(string(tt.sev), func(t *testing.T) {
			got := SeverityRank(tt.sev)
			if got != tt.want {
				t.Errorf("SeverityRank(%v): got %d, want %d", tt.sev, got, tt.want)
			}
		})
	}

	// The ordering is what every filter and gate depends on, so it is asserted
	// as an ordering rather than only as five numbers.
	ordered := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(ordered); i++ {
		if SeverityRank(ordered[i]) <= SeverityRank(ordered[i-1]) {
			t.Errorf("%s does not rank above %s", ordered[i], ordered[i-1])
		}
	}
	if SeverityRank(ordered[0]) <= SeverityRank(Severity("unknown")) {
		t.Error("the least severe real level does not rank above an unrecognised one")
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
	// Verify the canonical string values providers must emit
	tests := []struct {
		pt   PrincipalType
		want string
	}{
		{PrincipalUser, "user"},
		{PrincipalRole, "role"},
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

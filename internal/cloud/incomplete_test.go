package cloud

import "testing"

type reportingProvider struct{ msgs []string }

func (r reportingProvider) Incomplete() []string { return r.msgs }

type silentProvider struct{}

func TestIncomplete_MergesReporters(t *testing.T) {
	// Scanners take a slice of providers, so a command needs the union — and a
	// provider that does not implement the interface must not be an error, just
	// a provider with nothing to report.
	providers := []any{
		reportingProvider{msgs: []string{"list roles page: AccessDenied"}},
		silentProvider{},
		reportingProvider{msgs: []string{"bucket prod-data: versioning check failed"}},
	}

	got := Incomplete(providers)
	if len(got) != 2 {
		t.Fatalf("expected both reporters merged, got %v", got)
	}
}

func TestIncomplete_AllSilentIsNil(t *testing.T) {
	// The signal drives an exit code, so "everything was readable" has to be
	// distinguishable from "one empty message".
	if got := Incomplete([]any{silentProvider{}, reportingProvider{}}); got != nil {
		t.Errorf("a fully readable run must report nothing, got %v", got)
	}
}

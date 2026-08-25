package cloud

import (
	"errors"
	"testing"
)

// MarkUnread is what separates "this setting is off" from "this probe did not
// answer" for a repository sweep. Every boolean on RepoSettings has a false
// meaning both, and only this map says which one a caller is looking at.
func TestRepoSettingsMarkUnread(t *testing.T) {
	var s RepoSettings

	if len(s.Unread) != 0 {
		t.Fatal("a fresh RepoSettings reports unread probes")
	}

	s.MarkUnread("branch protection", errors.New("dial tcp: connection refused"))
	if len(s.Unread) != 1 {
		t.Fatalf("got %d unread entries, want 1", len(s.Unread))
	}
	if got := s.Unread["branch protection"]; got != "dial tcp: connection refused" {
		t.Errorf("the record does not carry what the tool said: %q", got)
	}

	// A second probe is recorded alongside rather than replacing the first: a
	// sweep that lost half its failures reports a smaller outage than happened.
	s.MarkUnread("Dependabot alerts", errors.New("HTTP 403: rate limit exceeded"))
	if len(s.Unread) != 2 {
		t.Fatalf("got %d unread entries after two probes, want 2", len(s.Unread))
	}

	// Re-marking the same probe replaces its reason rather than duplicating it.
	s.MarkUnread("branch protection", errors.New("context deadline exceeded"))
	if len(s.Unread) != 2 {
		t.Errorf("re-marking a probe changed the entry count to %d", len(s.Unread))
	}
	if got := s.Unread["branch protection"]; got != "context deadline exceeded" {
		t.Errorf("re-marking did not replace the reason: %q", got)
	}
}

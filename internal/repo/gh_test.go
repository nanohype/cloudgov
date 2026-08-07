package repo

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// stubGH replays canned gh output keyed by a substring of the invocation, so the
// argument construction is asserted rather than assumed. GHReader.Run is
// injectable for exactly this: the whole reader runs with no token and no
// network.
type stubGH struct {
	byArg map[string]string
	errs  map[string]error
	calls []string
}

// Longest key wins. Every protection and dependabot URL contains the repo URL,
// so a plain substring match over a Go map resolves by iteration order — which
// is randomised, and made this stub answer the protection call with the repo
// metadata about half the time. The reader was right; the fixture was not.
func (s *stubGH) run(_ context.Context, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	s.calls = append(s.calls, joined)

	bestErr, bestErrLen := error(nil), -1
	for k, err := range s.errs {
		if strings.Contains(joined, k) && len(k) > bestErrLen {
			bestErr, bestErrLen = err, len(k)
		}
	}
	bestOut, bestOutLen := "", -1
	for k, out := range s.byArg {
		if strings.Contains(joined, k) && len(k) > bestOutLen {
			bestOut, bestOutLen = out, len(k)
		}
	}
	if bestErrLen > bestOutLen {
		return nil, bestErr
	}
	if bestOutLen >= 0 {
		return []byte(bestOut), nil
	}
	return nil, errors.New("no stub for: " + joined)
}

func newStub(byArg map[string]string, errs map[string]error) (*GHReader, *stubGH) {
	s := &stubGH{byArg: byArg, errs: errs}
	return &GHReader{Run: s.run}, s
}

func TestGHReader_ListReposSkipsBlankLines(t *testing.T) {
	r, s := newStub(map[string]string{"repo list": "eks-gitops\n\nlanding-zone\n"}, nil)
	got, err := r.ListRepos(context.Background(), "nanohype")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 || got[0] != "eks-gitops" || got[1] != "landing-zone" {
		t.Fatalf("got %v want [eks-gitops landing-zone]", got)
	}
	if !strings.Contains(s.calls[0], "isArchived") {
		t.Errorf("the listing must exclude archived repos at the source: %q", s.calls[0])
	}
}

const repoMeta = `{"private":false,"archived":false,"def":"main"}`

// The three ways protection can be absent are three different facts with three
// different remedies. Collapsing them is how "upgrade your plan" gets filed as
// "add a required check".
func TestGHReader_DistinguishesTheThreeUnprotectedStates(t *testing.T) {
	t.Run("no rule at all", func(t *testing.T) {
		r, _ := newStub(map[string]string{"repos/nanohype/x": repoMeta},
			map[string]error{"branches/main/protection": errors.New("Branch not protected")})
		s, err := r.Settings(context.Background(), "nanohype", "x")
		if err != nil {
			t.Fatalf("settings: %v", err)
		}
		if s.Protected || s.ProtectionUnavailable {
			t.Errorf("an unprotected branch is neither protected nor unavailable: %+v", s)
		}
	})

	t.Run("unavailable on plan", func(t *testing.T) {
		r, _ := newStub(map[string]string{"repos/nanohype/x": repoMeta},
			map[string]error{"branches/main/protection": errors.New("Upgrade to GitHub Pro or make this repository public")})
		s, _ := r.Settings(context.Background(), "nanohype", "x")
		if !s.ProtectionUnavailable {
			t.Errorf("a plan refusal must be recorded as unavailable, not as unprotected: %+v", s)
		}
		if s.Protected {
			t.Errorf("unavailable must not read as protected: %+v", s)
		}
	})

	t.Run("rule requiring nothing", func(t *testing.T) {
		r, _ := newStub(map[string]string{
			"repos/nanohype/x --jq":    repoMeta,
			"branches/main/protection": `{"required_status_checks":{"strict":false,"contexts":[]},"enforce_admins":{"Enabled":false}}`,
		}, nil)
		s, _ := r.Settings(context.Background(), "nanohype", "x")
		if !s.Protected {
			t.Fatalf("a rule that exists must read as protected: %+v", s)
		}
		if len(s.RequiredChecks) != 0 {
			t.Errorf("this rule requires nothing: %+v", s.RequiredChecks)
		}
	})
}

func TestGHReader_ReadsProtectionAndDependabot(t *testing.T) {
	r, _ := newStub(map[string]string{
		"repos/nanohype/eks-gitops --jq": repoMeta,
		"branches/main/protection":       `{"required_status_checks":{"strict":true,"contexts":["lint","validate"]},"enforce_admins":{"Enabled":true},"allow_force_pushes":{"Enabled":false},"allow_deletions":{"Enabled":false}}`,
		"vulnerability-alerts":           "",
		"automated-security-fixes":       `{"enabled":true}`,
		"dependabot/alerts?state=open":   "4",
	}, nil)

	s, err := r.Settings(context.Background(), "nanohype", "eks-gitops")
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	if len(s.RequiredChecks) != 2 || !s.StrictChecks || !s.EnforceAdmins {
		t.Errorf("protection not read through: %+v", s)
	}
	// 204 vs 404 — gh exits non-zero on 404, so absence of an error is the signal.
	if !s.AlertsEnabled || !s.SecurityUpdatesEnabled {
		t.Errorf("dependabot state not read through: %+v", s)
	}
	if s.OpenAlerts != 4 {
		t.Errorf("open alerts: got %d want 4", s.OpenAlerts)
	}
}

func TestGHReader_DependabotDisabledIsNotAnError(t *testing.T) {
	// A 404 on either endpoint means the feature is off, which is a finding
	// rather than a failure to read.
	r, _ := newStub(map[string]string{
		"repos/nanohype/x --jq":    repoMeta,
		"branches/main/protection": `{"required_status_checks":{"contexts":["build"]}}`,
	}, map[string]error{
		"vulnerability-alerts":         errors.New("404"),
		"automated-security-fixes":     errors.New("404"),
		"dependabot/alerts?state=open": errors.New("403"),
	})
	s, err := r.Settings(context.Background(), "nanohype", "x")
	if err != nil {
		t.Fatalf("disabled dependabot must not fail the read: %v", err)
	}
	if s.AlertsEnabled || s.SecurityUpdatesEnabled || s.OpenAlerts != 0 {
		t.Errorf("disabled features must read as disabled: %+v", s)
	}
}

func TestGHReader_UnreadableMetadataIsAnError(t *testing.T) {
	// The repo itself failing to read is different from a feature being off,
	// and must surface so Audit reports the repository as unread.
	r, _ := newStub(nil, map[string]error{"repos/nanohype/x --jq": errors.New("401 Bad credentials")})
	if _, err := r.Settings(context.Background(), "nanohype", "x"); err == nil {
		t.Fatal("unreadable repo metadata must be an error, not an empty settings struct")
	}
}

func TestGHReader_MalformedMetadataIsAnError(t *testing.T) {
	r, _ := newStub(map[string]string{"repos/nanohype/x --jq": "not json"}, nil)
	if _, err := r.Settings(context.Background(), "nanohype", "x"); err == nil {
		t.Fatal("unparseable metadata must be an error rather than a zero-valued repo")
	}
}

// A name that gh would read as a flag rather than a path segment is the real
// risk in building an argv from caller input — there is no shell, so there is no
// command injection, but `--method` in an org position turns a read into
// something else. Validation removes the premise rather than annotating around
// it.
func TestGHReader_RejectsNamesGhWouldReadAsFlags(t *testing.T) {
	r, s := newStub(map[string]string{"repo list": "x"}, nil)

	bad := []string{"-org", "--method", "a/b", "a b", "", strings.Repeat("x", 101)}
	for _, name := range bad {
		if _, err := r.ListRepos(context.Background(), name); err == nil {
			t.Errorf("ListRepos accepted %q as an org", name)
		}
		if _, err := r.Settings(context.Background(), "nanohype", name); err == nil {
			t.Errorf("Settings accepted %q as a repo", name)
		}
		if _, err := r.Settings(context.Background(), name, "eks-gitops"); err == nil {
			t.Errorf("Settings accepted %q as an org", name)
		}
	}
	if len(s.calls) != 0 {
		t.Errorf("a rejected name must never reach gh, got calls: %v", s.calls)
	}
}

func TestGHReader_AcceptsRealNames(t *testing.T) {
	// Without this the rejection test above passes on a validator that refuses
	// everything.
	r, _ := newStub(map[string]string{"repo list": "eks-gitops"}, nil)
	for _, name := range []string{"nanohype", "eks-agent-platform", "nanohype.dev", "a_b", "x1"} {
		if _, err := r.ListRepos(context.Background(), name); err != nil {
			t.Errorf("ListRepos rejected the legitimate org %q: %v", name, err)
		}
	}
}

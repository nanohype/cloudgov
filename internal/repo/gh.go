package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// GitHub's own character set for an org or repository name. Every value this
// package interpolates into a gh argument is checked against it first.
//
// exec.Command passes argv directly with no shell, so there is no command
// injection to have — but a name carrying a leading dash would be read by gh as
// a FLAG rather than a path segment, which is a real way to turn a read into
// something else. Validating removes the premise instead of annotating around
// it, and gives gosec's G204 nothing left to be right about.
var ghName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

func checkName(kind, v string) error {
	if !ghName.MatchString(v) {
		return fmt.Errorf("%s %q is not a valid GitHub name", kind, v)
	}
	return nil
}

// GHReader reads repository settings through the `gh` CLI.
//
// gh rather than a GitHub SDK for one reason: it already holds the operator's
// credential. cloudgov reads AWS through the ambient AWS credential chain and
// asks the human for nothing; doing the same for GitHub keeps that property
// rather than introducing the one token this tool would have to be handed.
type GHReader struct {
	// Run executes a gh invocation. Injectable so the argument construction is
	// testable without a network or a token.
	Run func(ctx context.Context, args ...string) ([]byte, error)
}

// ghCallTimeout bounds one gh invocation.
//
// The caller's context carries cancellation on SIGINT/SIGTERM but no deadline,
// and cancellation needs a human to press something. An unattended run — a CI
// gate, an MCP tool call — has nobody to press it, so a gh process that hangs on
// a stalled connection would hang the sweep with no ceiling. This is the same
// two-layer reasoning the AWS provider states: the context is for the human, the
// timeout is for the machine.
//
// A deadline exceeded here surfaces as the HIGH finding the audit already emits
// for an unreadable repository, which is the right reading — an unreadable
// repository is itself the governance gap.
const ghCallTimeout = 30 * time.Second

// NewGHReader returns a reader backed by the gh CLI on PATH.
func NewGHReader() *GHReader {
	return &GHReader{Run: func(ctx context.Context, args ...string) ([]byte, error) {
		cctx, cancel := context.WithTimeout(ctx, ghCallTimeout)
		defer cancel()
		// The command is the constant "gh"; every argument is either a literal
		// here or a name checkName has already accepted. No shell is involved.
		out, err := exec.CommandContext(cctx, "gh", args...).Output() // #nosec G204 -- constant command; args are literals plus ghName-validated tokens
		if err != nil {
			// Both the text and the type are carried. The text is what an
			// operator reads; the type is what any future classifier would need,
			// and an error that has lost it forces the next layer to decide from
			// an exit status — which conflates an unreachable API, a denied
			// request and a missing object into one number. Wrapping with %w
			// keeps errors.As working through this boundary.
			var ee *exec.ExitError
			if ok := asExitError(err, &ee); ok && len(ee.Stderr) > 0 {
				return out, fmt.Errorf("gh %s: %s: %w",
					strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)), err)
			}
			return out, fmt.Errorf("gh %s: %w", strings.Join(args, " "), err)
		}
		return out, nil
	}}
}

// asExitError unwraps to *exec.ExitError. errors.As rather than a type assertion:
// an assertion only matches when the ExitError is the outermost error, so any
// wrapping upstream silently turns "gh failed with this stderr" into the generic
// branch and the actual diagnostic is dropped.
func asExitError(err error, target **exec.ExitError) bool {
	return errors.As(err, target)
}

// ListRepos returns every non-archived repository in the org.
func (g *GHReader) ListRepos(ctx context.Context, org string) ([]string, error) {
	if err := checkName("org", org); err != nil {
		return nil, err
	}
	out, err := g.Run(ctx, "repo", "list", org, "--limit", "200",
		"--json", "name,isArchived", "--jq", `.[]|select(.isArchived|not)|.name`)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			names = append(names, l)
		}
	}
	return names, nil
}

type ghProtection struct {
	RequiredStatusChecks *struct {
		Strict   bool     `json:"strict"`
		Contexts []string `json:"contexts"`
	} `json:"required_status_checks"`
	EnforceAdmins    *struct{ Enabled bool } `json:"enforce_admins"`
	AllowForcePushes *struct{ Enabled bool } `json:"allow_force_pushes"`
	AllowDeletions   *struct{ Enabled bool } `json:"allow_deletions"`
	Message          string                  `json:"message"`
}

// Settings reads one repository's protection and Dependabot state.
//
// The three ways protection can be absent are kept distinct, because they are
// three different facts with three different remedies: no rule at all, a rule
// requiring nothing, and a plan on which protection does not exist. Collapsing
// them is how "upgrade your plan" gets filed as "add a required check".
func (g *GHReader) Settings(ctx context.Context, org, name string) (cloud.RepoSettings, error) {
	s := cloud.RepoSettings{Name: name, DefaultRef: "main"}
	if err := checkName("org", org); err != nil {
		return s, err
	}
	if err := checkName("repo", name); err != nil {
		return s, err
	}

	meta, err := g.Run(ctx, "api", fmt.Sprintf("repos/%s/%s", org, name),
		"--jq", `{private:.private,archived:.archived,def:.default_branch}`)
	if err != nil {
		return s, err
	}
	var m struct {
		Private  bool   `json:"private"`
		Archived bool   `json:"archived"`
		Def      string `json:"def"`
	}
	if err := json.Unmarshal(meta, &m); err != nil {
		return s, fmt.Errorf("parse repo metadata for %s: %w", name, err)
	}
	s.Private, s.Archived = m.Private, m.Archived
	if m.Def != "" {
		if err := checkName("default branch", m.Def); err != nil {
			return s, err
		}
		s.DefaultRef = m.Def
	}

	prot, perr := g.Run(ctx, "api", fmt.Sprintf("repos/%s/%s/branches/%s/protection", org, name, s.DefaultRef))
	switch {
	case perr != nil && strings.Contains(perr.Error(), "Upgrade to GitHub Pro"):
		s.ProtectionUnavailable = true
	case perr != nil:
		// "Branch not protected" is the ordinary unprotected case, not an error.
		s.Protected = false
	default:
		var p ghProtection
		if err := json.Unmarshal(prot, &p); err != nil {
			return s, fmt.Errorf("parse protection for %s: %w", name, err)
		}
		if strings.Contains(p.Message, "Upgrade to GitHub Pro") {
			s.ProtectionUnavailable = true
			break
		}
		if strings.Contains(p.Message, "not protected") {
			break
		}
		s.Protected = true
		if p.RequiredStatusChecks != nil {
			s.RequiredChecks = p.RequiredStatusChecks.Contexts
			s.StrictChecks = p.RequiredStatusChecks.Strict
		}
		if p.EnforceAdmins != nil {
			s.EnforceAdmins = p.EnforceAdmins.Enabled
		}
		if p.AllowForcePushes != nil {
			s.AllowForcePushes = p.AllowForcePushes.Enabled
		}
		if p.AllowDeletions != nil {
			s.AllowDeletions = p.AllowDeletions.Enabled
		}
	}

	// 204 = enabled, 404 = disabled. gh exits non-zero on 404, so absence of an
	// error is the signal.
	if _, err := g.Run(ctx, "api", fmt.Sprintf("repos/%s/%s/vulnerability-alerts", org, name)); err == nil {
		s.AlertsEnabled = true
	}
	if _, err := g.Run(ctx, "api", fmt.Sprintf("repos/%s/%s/automated-security-fixes", org, name)); err == nil {
		s.SecurityUpdatesEnabled = true
	}
	if alerts, err := g.Run(ctx, "api",
		fmt.Sprintf("repos/%s/%s/dependabot/alerts?state=open&per_page=100", org, name),
		"--jq", "length"); err == nil {
		var n int
		if json.Unmarshal([]byte(strings.TrimSpace(string(alerts))), &n) == nil {
			s.OpenAlerts = n
		}
	}

	return s, nil
}

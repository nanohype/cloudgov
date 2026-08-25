// Package repo audits GitHub repository settings against a committed expected
// shape.
//
// These settings are the one part of the delivery path no gate inside a repo can
// see. A repo can have a full CI matrix, a protection rule that requires none of
// it, and nothing anywhere will say so — which is the state landing-zone was in
// while every merge to it became live AWS infrastructure.
//
// The expected shape is committed, so drift is a diff rather than a memory, and
// a repository added tomorrow is measured on the same day it appears.
package repo

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// Reader is the narrow GitHub surface this audit needs, following the
// IdentityReader precedent: an interface the audit owns, so the whole thing is
// exercised against fakes without a token or a network.
type Reader interface {
	// ListRepos returns every non-archived repository in the org.
	ListRepos(ctx context.Context, org string) ([]string, error)
	// Settings reads one repository's protection and Dependabot state.
	Settings(ctx context.Context, org, repo string) (cloud.RepoSettings, error)
}

// Expected is the committed shape every repository is measured against.
type Expected struct {
	// RequiredChecks a repo must require on its default branch, by repo name.
	// A repo absent from this map is still measured on everything else — an
	// omission must not read as an exemption.
	RequiredChecks map[string][]string `yaml:"requiredChecks"`
	// EnforceAdmins, when true, means an admin may not merge past required
	// checks.
	EnforceAdmins bool `yaml:"enforceAdmins"`
	// AllowForcePushes / AllowDeletions on the default branch.
	AllowForcePushes bool `yaml:"allowForcePushes"`
	AllowDeletions   bool `yaml:"allowDeletions"`
	// Dependabot expectations.
	AlertsEnabled          bool `yaml:"alertsEnabled"`
	SecurityUpdatesEnabled bool `yaml:"securityUpdatesEnabled"`
	// Exempt repos, each with a stated reason. An entry here is a decision; a
	// repo silently missing from the sweep is an accident that reads the same.
	Exempt map[string]string `yaml:"exempt"`
}

// Audit compares every repository in the org against the expected shape.
// Audit compares an organization's repositories against the committed expected
// shape.
//
// The second return is the run's unread list: repositories the sweep was asked to
// examine and could not. It is separate from the findings because it answers a
// different question — a repository nobody could read is not a repository with a
// governance gap, and reporting it as one hands a merge gate a breach that is
// really an outage.
func Audit(ctx context.Context, r Reader, org string, exp Expected) ([]cloud.RepoFinding, []string, error) {
	names, err := r.ListRepos(ctx, org)
	if err != nil {
		return nil, nil, fmt.Errorf("list repos in %s: %w", org, err)
	}
	sort.Strings(names)

	var out []cloud.RepoFinding
	var unread []string
	for _, name := range names {
		if _, ok := exp.Exempt[name]; ok {
			continue
		}
		s, err := r.Settings(ctx, org, name)
		if err != nil {
			// A repo whose settings cannot be read is recorded, never skipped —
			// skipping is how a sweep reports a clean org over repositories it
			// never managed to look at.
			//
			// It is recorded as UNREAD rather than as a finding, because an
			// error from `gh` does not carry enough to name a cause: the same
			// failure is returned for an unreachable API, an unauthenticated CLI,
			// a rate limit, a deadline, and a token that genuinely lacks the
			// scope. Filing it as a finding asserts one of those, which is a
			// guess in the shape of a diagnosis and costs the operator a search
			// that cannot succeed — and a merge gate reading NO_BRANCH_PROTECTION
			// at HIGH sees a governance breach where there is an outage.
			//
			// So the tool's own distinction applies here as everywhere else: a
			// thing it could not observe is not a thing it found. The message
			// carries what gh actually said, and nothing else.
			unread = append(unread, fmt.Sprintf("%s/%s: settings could not be read: %v", org, name, err))
			continue
		}
		if s.Archived {
			continue
		}
		// A probe that did not answer is recorded as unread rather than left to
		// be read as "off" by the checks below. Every boolean on RepoSettings has
		// a false that means the setting is disabled and, without this, a false
		// that means the read failed.
		for probe, reason := range s.Unread {
			unread = append(unread, fmt.Sprintf("%s/%s: %s could not be read: %s", org, name, probe, reason))
		}
		out = append(out, auditOne(s, exp)...)
	}
	return out, unread, nil
}

func auditOne(s cloud.RepoSettings, exp Expected) []cloud.RepoFinding {
	var out []cloud.RepoFinding
	add := func(sev cloud.Severity, t cloud.RepoFindingType, detail, fix string) {
		out = append(out, cloud.RepoFinding{
			Severity: sev, Type: t, Repo: s.Name, Detail: detail, Remediation: fix,
		})
	}

	switch {
	case s.ProtectionUnavailable:
		// Not a misconfiguration, and no setting fixes it. Reported so the
		// exposure is a stated fact rather than an absence that reads as
		// compliance.
		add(cloud.SeverityHigh, cloud.RepoUnprotectable,
			"branch protection is unavailable for this repository on the current plan",
			"Either make the repository public, or upgrade the plan, or record in the "+
				"ledger that this repository is permanently unprotected by choice. The one "+
				"unacceptable outcome is leaving it unstated.")

	case s.Unread["branch protection"] != "":
		// The read failed, so `Protected` is a zero value rather than an answer.
		// The unread record carries this; emitting NO_BRANCH_PROTECTION here
		// would report a breach derived from a field nothing filled in.

	case !s.Protected:
		add(cloud.SeverityHigh, cloud.RepoNoProtection,
			fmt.Sprintf("%s has no branch protection rule", s.DefaultRef),
			"Add a protection rule with the repository's own required checks.")

	default:
		if len(s.RequiredChecks) == 0 {
			add(cloud.SeverityHigh, cloud.RepoNoRequiredChecks,
				"a protection rule exists and requires no status check",
				"Add the repository's required checks. This state is worse than no rule: "+
					"the repository reads as protected everywhere while admitting a PR whose "+
					"entire CI matrix is red.")
		}
		if want, ok := exp.RequiredChecks[s.Name]; ok {
			have := map[string]bool{}
			for _, c := range s.RequiredChecks {
				have[c] = true
			}
			var missing []string
			for _, c := range want {
				if !have[c] {
					missing = append(missing, c)
				}
			}
			if len(missing) > 0 {
				add(cloud.SeverityMedium, cloud.RepoMissingRequiredCheck,
					fmt.Sprintf("expected checks not required: %s", strings.Join(missing, ", ")),
					"Add them to the protection rule, or drop them from the expected shape "+
						"if the job no longer exists.")
			}
		}
		if exp.EnforceAdmins && !s.EnforceAdmins {
			add(cloud.SeverityMedium, cloud.RepoAdminsExempt,
				"enforce_admins is off — an admin merges past every required check",
				"Enable enforce_admins. Note this removes `gh pr merge --admin`, which is "+
					"the escape hatch when a required check is stuck.")
		}
		if !exp.AllowForcePushes && s.AllowForcePushes {
			add(cloud.SeverityHigh, cloud.RepoForcePushAllowed,
				fmt.Sprintf("force pushes are allowed on %s", s.DefaultRef),
				"Disable force pushes on the default branch.")
		}
		if !exp.AllowDeletions && s.AllowDeletions {
			add(cloud.SeverityHigh, cloud.RepoDeletionAllowed,
				fmt.Sprintf("%s can be deleted", s.DefaultRef),
				"Disable branch deletion on the default branch.")
		}
	}

	if exp.AlertsEnabled && !s.AlertsEnabled && s.Unread["Dependabot alerts"] == "" {
		add(cloud.SeverityHigh, cloud.RepoAlertsDisabled,
			"Dependabot vulnerability alerts are disabled",
			"Enable them. Without alerts an advisory against this dependency tree is "+
				"reported to nobody, and is found only when a PR happens to touch the repo.")
	}
	if exp.SecurityUpdatesEnabled && !s.SecurityUpdatesEnabled && s.Unread["Dependabot security updates"] == "" {
		add(cloud.SeverityMedium, cloud.RepoSecurityUpdatesDisabled,
			"Dependabot security updates are disabled — no remediation PR opens by itself",
			"Enable automated security fixes. Alerts alone tell somebody; they do not "+
				"fix anything, so the same advisory is resolved by hand once per repository "+
				"that carries the dependency.")
	}
	if s.OpenAlerts > 0 {
		add(cloud.SeverityHigh, cloud.RepoOpenAlerts,
			fmt.Sprintf("%d open Dependabot alert(s)", s.OpenAlerts),
			"Read them. An open alert is an advisory nobody has decided about, and the "+
				"decision does not get easier with age.")
	}

	return out
}

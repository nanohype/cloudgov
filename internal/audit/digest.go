package audit

import (
	"sort"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// Example is one finding lifted out of a report for a digest — enough to
// recognise the thing without the caller reaching back into the domain types.
type Example struct {
	Severity string
	Type     string
	Provider string
	Resource string
	Detail   string
}

// TopFindings returns up to n findings, highest severity first, drawn from every
// domain the report carries.
//
// It lives beside the Report rather than in the command that renders it, so the
// domain list sits next to the struct that defines it. The version in cmd/
// covered four of the seven domains while its comment said "across all domains",
// and nothing made the omission visible: a Slack digest could report Critical: 1
// with "certs" among its domains and no certificate anywhere in the examples,
// because a cert finding is a Critical the summary counts and the examples never
// reached. Adding a domain to Report and not to this function is now a change in
// one file rather than two.
func (r *Report) TopFindings(n int) []Example {
	if r == nil || n <= 0 {
		return nil
	}

	var all []Example
	for _, f := range r.IAM {
		resource := ""
		if f.Principal != nil {
			resource = f.Principal.Name
		}
		all = append(all, Example{
			Severity: string(f.Severity), Type: string(f.Type),
			Provider: f.Provider, Resource: resource, Detail: f.Detail,
		})
	}
	for _, f := range r.Storage {
		all = append(all, Example{
			Severity: string(f.Severity), Type: string(f.Type),
			Provider: f.Provider, Resource: f.Bucket, Detail: f.Detail,
		})
	}
	for _, f := range r.Network {
		all = append(all, Example{
			Severity: string(f.Severity), Type: string(f.Type),
			Provider: f.Provider, Resource: f.Resource, Detail: f.Detail,
		})
	}
	for _, f := range r.Secrets {
		all = append(all, Example{
			Severity: string(f.Severity), Type: string(f.Type),
			Provider: f.Provider, Resource: f.Resource, Detail: f.Detail,
		})
	}
	for _, f := range r.Certs {
		all = append(all, Example{
			Severity: string(f.Severity), Type: string(f.Status),
			Provider: f.Provider, Resource: f.Domain, Detail: f.Detail,
		})
	}
	for _, f := range r.Tags {
		all = append(all, Example{
			Severity: string(f.Severity), Type: "MISSING_TAGS",
			Provider: f.Provider, Resource: f.ResourceID, Detail: missingTagDetail(f),
		})
	}
	// An orphan carries a cost rather than a severity, and OrphanKind decides
	// whether it is reportable at all. Rendering it at the severity the summary
	// counts it under keeps the digest and the counts telling one story.
	for _, o := range r.Orphans {
		all = append(all, Example{
			Severity: string(cloud.SeverityLow), Type: string(o.Kind),
			Provider: o.Provider, Resource: o.ID, Detail: o.Detail,
		})
	}

	sort.SliceStable(all, func(i, j int) bool {
		return cloud.SeverityRank(cloud.Severity(all[i].Severity)) >
			cloud.SeverityRank(cloud.Severity(all[j].Severity))
	})
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func missingTagDetail(f cloud.TagFinding) string {
	if len(f.MissingTags) == 0 {
		return f.Detail
	}
	out := "missing " + f.MissingTags[0]
	for _, t := range f.MissingTags[1:] {
		out += ", " + t
	}
	return out
}

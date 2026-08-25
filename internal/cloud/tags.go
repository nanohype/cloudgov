package cloud

import (
	"context"
	"strings"
)

// TagFinding is a single resource missing required tags observation.
type TagFinding struct {
	Severity     Severity
	Provider     string
	ResourceID   string
	ResourceType string // "ec2:instance", "s3:bucket", "rds:db", etc.
	Region       string
	MissingTags  []string
	Detail       string
}

// ConditionalTag is a tag required only on certain resource kinds.
//
// The org tagging standard has one: BackupPolicy, required on the kinds AWS
// Backup can protect. It matters more than the flat tier and is easier to miss —
// a backup-eligible resource without the tag is never selected by the
// tag-matching backup plan, and nothing errors until a restore is attempted. It
// is the highest-probability coverage failure precisely because it produces no
// signal of its own.
type ConditionalTag struct {
	// Tag is the key the matching resources must carry.
	Tag string
	// Kinds are the resource-type prefixes this applies to, matched against
	// TagFinding.ResourceType's leading segment ("s3", "rds", "dynamodb").
	Kinds []string
}

// AppliesTo reports whether this rule covers a resource type such as
// "s3:bucket" or "rds:db".
func (c ConditionalTag) AppliesTo(resourceType string) bool {
	kind := resourceType
	if i := strings.Index(kind, ":"); i >= 0 {
		kind = kind[:i]
	}
	for _, k := range c.Kinds {
		if strings.EqualFold(kind, k) {
			return true
		}
	}
	return false
}

// TagRules is the whole tag policy a scan gates on: the keys every resource
// carries, and the keys required only on certain kinds.
type TagRules struct {
	Required    []string
	Conditional []ConditionalTag
}

// Empty reports whether these rules would gate on nothing.
func (r TagRules) Empty() bool {
	return len(r.Required) == 0 && len(r.Conditional) == 0
}

// RequiredOnly builds rules carrying only the flat tier, for callers that name
// keys directly rather than reading a published standard.
func RequiredOnly(keys ...string) TagRules {
	return TagRules{Required: keys}
}

// MissingFor returns the keys a resource of this type is missing: the flat tier
// every resource carries, plus whichever conditional rules cover this kind.
//
// One policy evaluated in one place, so a provider does not reimplement the
// comparison per resource kind — which is how a kind ends up gating on a
// different rule set than its siblings.
func (r TagRules) MissingFor(resourceType string, present map[string]struct{}) []string {
	var missing []string
	for _, key := range r.Required {
		if _, ok := present[key]; !ok {
			missing = append(missing, key)
		}
	}
	for _, rule := range r.Conditional {
		if !rule.AppliesTo(resourceType) {
			continue
		}
		if _, ok := present[rule.Tag]; !ok {
			missing = append(missing, rule.Tag)
		}
	}
	return missing
}

// TagProvider audits resources for missing required tags/labels.
type TagProvider interface {
	Provider
	AuditTags(ctx context.Context, rules TagRules) ([]TagFinding, error)
}

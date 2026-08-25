package cloud

import (
	"reflect"
	"testing"
)

func present(keys ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		out[k] = struct{}{}
	}
	return out
}

func TestConditionalTagAppliesTo(t *testing.T) {
	rule := ConditionalTag{Tag: "BackupPolicy", Kinds: []string{"s3", "rds", "dynamodb"}}
	for _, tc := range []struct {
		resourceType string
		want         bool
	}{
		{"s3:bucket", true},
		{"rds:db", true},
		{"dynamodb:table", true},
		// The kind is the leading segment, so a bare kind matches too.
		{"s3", true},
		// Case is not a discriminator: the standard writes service names and a
		// scanner writes lowercase prefixes.
		{"S3:bucket", true},
		{"ec2:instance", false},
		{"lambda:function", false},
		{"", false},
		// A prefix that merely starts with a covered kind is a different kind.
		{"s3control:accesspoint", false},
	} {
		if got := rule.AppliesTo(tc.resourceType); got != tc.want {
			t.Errorf("AppliesTo(%q) = %v, want %v", tc.resourceType, got, tc.want)
		}
	}
}

func TestTagRulesMissingFor(t *testing.T) {
	rules := TagRules{
		Required:    []string{"Environment", "Team"},
		Conditional: []ConditionalTag{{Tag: "BackupPolicy", Kinds: []string{"s3", "rds"}}},
	}

	for _, tc := range []struct {
		name         string
		resourceType string
		have         map[string]struct{}
		want         []string
	}{
		{"nothing tagged, kind covered", "s3:bucket", present(), []string{"Environment", "Team", "BackupPolicy"}},
		{"nothing tagged, kind not covered", "ec2:instance", present(), []string{"Environment", "Team"}},
		{
			// The case the conditional tier exists for: every flat key present,
			// and the resource still unprotected.
			"flat tier complete, conditional missing", "s3:bucket",
			present("Environment", "Team"), []string{"BackupPolicy"},
		},
		{"flat tier complete on an uncovered kind", "ec2:instance", present("Environment", "Team"), nil},
		{"everything present", "rds:db", present("Environment", "Team", "BackupPolicy"), nil},
		{"conditional present but flat missing", "s3:bucket", present("BackupPolicy"), []string{"Environment", "Team"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rules.MissingFor(tc.resourceType, tc.have)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("MissingFor(%q) = %v, want %v", tc.resourceType, got, tc.want)
			}
		})
	}
}

// The flat tier is reported in the order the standard declares it, so a report
// reads the same way twice and a diff between runs is a real change.
func TestTagRulesPreservesRequiredOrder(t *testing.T) {
	rules := TagRules{Required: []string{"Environment", "ManagedBy", "Project", "Team"}}
	got := rules.MissingFor("ec2:instance", present("Project"))
	want := []string{"Environment", "ManagedBy", "Team"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MissingFor = %v, want %v in declaration order", got, want)
	}
}

func TestTagRulesEmpty(t *testing.T) {
	if !(TagRules{}).Empty() {
		t.Error("zero-value rules report as non-empty")
	}
	if (TagRules{Required: []string{"Team"}}).Empty() {
		t.Error("rules with a required key report as empty")
	}
	// Conditional-only rules gate on something, so they are not empty. Reporting
	// them empty would make a standard whose flat tier is empty silently skip the
	// conditional tier as well.
	if (TagRules{Conditional: []ConditionalTag{{Tag: "BackupPolicy", Kinds: []string{"s3"}}}}).Empty() {
		t.Error("conditional-only rules report as empty, so they would never be evaluated")
	}
}

func TestRequiredOnly(t *testing.T) {
	rules := RequiredOnly("Environment", "Team")
	if !reflect.DeepEqual(rules.Required, []string{"Environment", "Team"}) {
		t.Errorf("Required = %v", rules.Required)
	}
	if len(rules.Conditional) != 0 {
		t.Errorf("RequiredOnly produced %d conditional rule(s)", len(rules.Conditional))
	}
	if !RequiredOnly().Empty() {
		t.Error("RequiredOnly() with no keys is not empty")
	}
}

package tags

import (
	"os"
	"testing"
)

// A probe against the real published standard when a checkout is present. It is
// skipped rather than failed when the file is absent, because a developer
// machine without the standards checkout is a normal state — but where the file
// IS present, the fixtures above must agree with it, or they are testing a shape
// the standard no longer publishes.
func TestLoadRulesAgainstThePublishedStandard(t *testing.T) {
	path := os.Getenv("CLOUDGOV_RESOURCE_TAGGING_STANDARD")
	if path == "" {
		t.Skip("set CLOUDGOV_RESOURCE_TAGGING_STANDARD to a published resource-tagging.json to run this probe")
	}
	rules, gaps, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules against the published standard: %v", err)
	}
	t.Logf("required (%d): %v", len(rules.Required), rules.Required)
	for _, c := range rules.Conditional {
		t.Logf("conditional: %s on %v", c.Tag, c.Kinds)
	}
	t.Logf("unenforceable: %v", gaps)

	full := map[string]struct{}{}
	for _, k := range rules.Required {
		full[k] = struct{}{}
	}
	if missing := rules.MissingFor("s3:bucket", full); len(missing) == 0 {
		t.Error("the published standard yielded no conditional requirement on an S3 bucket")
	} else {
		t.Logf("fully flat-tagged s3:bucket still missing: %v", missing)
	}
	if missing := rules.MissingFor("ec2:instance", full); len(missing) != 0 {
		t.Errorf("a fully flat-tagged EC2 instance reported %v", missing)
	}
}

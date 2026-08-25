package tags

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "resource-tagging.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

const validStandard = `{
  "kind": "nanohype/standards/resource-tagging",
  "content": {
    "required_by_surface": {
      "aws": ["Environment", "ManagedBy", "CostCenter"],
      "k8s": ["environment"]
    }
  }
}`

func TestLoadRules(t *testing.T) {
	t.Run("valid returns aws keys", func(t *testing.T) {
		got, _, err := LoadRules(writeTemp(t, validStandard))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"Environment", "ManagedBy", "CostCenter"}
		if len(got.Required) != len(want) {
			t.Fatalf("got %v want %v", got.Required, want)
		}
		for i := range want {
			if got.Required[i] != want[i] {
				t.Errorf("key %d: got %q want %q", i, got.Required[i], want[i])
			}
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		if _, _, err := LoadRules(filepath.Join(t.TempDir(), "nope.json")); err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("bad json errors", func(t *testing.T) {
		if _, _, err := LoadRules(writeTemp(t, "{not json")); err == nil {
			t.Error("expected error for bad json")
		}
	})

	t.Run("wrong kind errors", func(t *testing.T) {
		body := `{"kind":"nanohype/standards/llm-policy","content":{"required_by_surface":{"aws":["Environment"]}}}`
		if _, _, err := LoadRules(writeTemp(t, body)); err == nil {
			t.Error("expected error for wrong kind")
		}
	})

	t.Run("empty aws list errors", func(t *testing.T) {
		body := `{"kind":"nanohype/standards/resource-tagging","content":{"required_by_surface":{"k8s":["environment"]}}}`
		if _, _, err := LoadRules(writeTemp(t, body)); err == nil {
			t.Error("expected error for empty aws list")
		}
	})
}

// The conditional tier is the half that was unimplemented, and it is the half
// the standard singles out: a backup-eligible resource without a BackupPolicy
// tag is never selected by the tag-matching backup plan, and nothing errors
// until a restore is attempted. The standard names cloudgov as one of two
// detective enforcers for it.
const conditionalStandard = `{
  "kind": "nanohype/standards/resource-tagging",
  "content": {
    "required_by_surface": { "aws": ["Environment", "Team"] },
    "conditional_requirements": [
      {
        "dimension": "backup-policy",
        "surface": "aws",
        "tag": "BackupPolicy",
        "required_on_kinds": ["Aurora", "RDS", "DynamoDB", "S3", "EFS"]
      },
      {
        "dimension": "k8s-only",
        "surface": "k8s",
        "tag": "IgnoredHere",
        "required_on_kinds": ["Deployment"]
      }
    ]
  }
}`

func TestLoadRulesReadsTheConditionalTier(t *testing.T) {
	rules, unenforceable, err := LoadRules(writeTemp(t, conditionalStandard))
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	if len(rules.Conditional) != 1 {
		t.Fatalf("got %d conditional rule(s), want 1 (the aws one; the k8s rule is another surface)", len(rules.Conditional))
	}
	rule := rules.Conditional[0]
	if rule.Tag != "BackupPolicy" {
		t.Errorf("conditional tag = %q, want BackupPolicy", rule.Tag)
	}

	// Kinds this tool enumerates are covered.
	for _, resourceType := range []string{"s3:bucket", "rds:db", "dynamodb:table"} {
		if !rule.AppliesTo(resourceType) {
			t.Errorf("the BackupPolicy rule does not cover %s, which cloudgov enumerates", resourceType)
		}
	}
	// Kinds it does not are excluded rather than silently matching nothing.
	for _, resourceType := range []string{"ec2:instance", "lambda:function", "sqs:queue"} {
		if rule.AppliesTo(resourceType) {
			t.Errorf("the BackupPolicy rule covers %s, which is not backup-eligible", resourceType)
		}
	}

	// Aurora and EFS are declared by the standard and unenumerable here. They
	// must be REPORTED, not dropped: a rule quietly covering fewer kinds than the
	// standard declares is a coverage claim nobody can check.
	joined := strings.Join(unenforceable, "; ")
	for _, kind := range []string{"Aurora", "EFS"} {
		if !strings.Contains(joined, kind) {
			t.Errorf("%s is declared by the standard and not enumerable here, and was not reported: %q", kind, joined)
		}
	}
	if strings.Contains(joined, "DynamoDB") {
		t.Errorf("DynamoDB is enumerable and was reported as unenforceable: %q", joined)
	}
}

// The whole point: a resource carrying every flat key still fails when it is
// backup-eligible and missing the conditional one.
func TestRulesFlagABackupEligibleResourceMissingOnlyBackupPolicy(t *testing.T) {
	rules, _, err := LoadRules(writeTemp(t, conditionalStandard))
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	fullyTagged := map[string]struct{}{"Environment": {}, "Team": {}}

	missing := rules.MissingFor("s3:bucket", fullyTagged)
	if len(missing) != 1 || missing[0] != "BackupPolicy" {
		t.Fatalf("a fully flat-tagged bucket reported %v; want exactly [BackupPolicy]", missing)
	}

	// The same tags on a kind the rule does not cover are complete.
	if missing := rules.MissingFor("ec2:instance", fullyTagged); len(missing) != 0 {
		t.Errorf("a fully tagged EC2 instance reported %v; BackupPolicy does not apply to it", missing)
	}

	// And a bucket that carries it is clean.
	protected := map[string]struct{}{"Environment": {}, "Team": {}, "BackupPolicy": {}}
	if missing := rules.MissingFor("s3:bucket", protected); len(missing) != 0 {
		t.Errorf("a bucket carrying every required tag reported %v", missing)
	}
}

// A standard with no conditional tier yields no conditional rules rather than an
// empty rule that matches everything.
func TestLoadRulesWithNoConditionalTier(t *testing.T) {
	rules, unenforceable, err := LoadRules(writeTemp(t, validStandard))
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if len(rules.Conditional) != 0 {
		t.Errorf("got %d conditional rule(s) from a standard declaring none", len(rules.Conditional))
	}
	if len(unenforceable) != 0 {
		t.Errorf("reported %v unenforceable from a standard declaring no conditional rules", unenforceable)
	}
}

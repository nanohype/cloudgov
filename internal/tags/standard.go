package tags

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// standardKind is the kind discriminator a resource-tagging standard file must
// declare. Guards against pointing --standard-file at the wrong JSON.
const standardKind = "nanohype/standards/resource-tagging"

// standardFile is the shape cloudgov reads from a published nanohype
// resource-tagging standard. The standard pre-renders the flat tier
// (content.required_by_surface.aws holds the PascalCase keys), so there is no
// rendering logic here — but the conditional tier is a separate list, and
// reading only the flat one is how a rule that the standard names cloudgov as
// enforcing goes unimplemented while the gate reports green.
type standardFile struct {
	Kind    string `json:"kind"`
	Content struct {
		RequiredBySurface map[string][]string `json:"required_by_surface"`
		Conditional       []struct {
			Surface        string   `json:"surface"`
			Tag            string   `json:"tag"`
			RequiredOnKind []string `json:"required_on_kinds"`
		} `json:"conditional_requirements"`
	} `json:"content"`
}

// awsKindPrefixes maps the standard's resource-kind vocabulary onto the
// ResourceType prefixes this tool's providers actually emit.
//
// The two vocabularies differ on purpose: the standard names AWS service
// concepts, and a scanner names what it enumerated ("rds:db"). Mapping them
// explicitly is what keeps an unmapped kind visible AS unmapped.
//
// Only kinds this tool enumerates appear here. Aurora and EFS are deliberately
// absent — cloudgov has no EFS auditor at all, and its RDS auditor paginates
// DescribeDBInstances, which does not return Aurora clusters. Mapping either one
// would produce a rule that matches nothing while reporting as enforced, which is
// worse than reporting it unenforceable: it converts a known gap into a silent
// one. LoadRules surfaces them instead, and the caller records them as
// incomplete observations.
var awsKindPrefixes = map[string][]string{
	"RDS":      {"rds"},
	"DynamoDB": {"dynamodb"},
	"S3":       {"s3"},
}

// LoadRules reads the tag policy from a nanohype resource-tagging standard JSON
// file: the required AWS keys every resource carries, plus the conditional rules
// that apply to particular kinds. The same file the SDK and MCP serve and CI
// gates on.
//
// A kind the standard names and this tool cannot enumerate is reported rather
// than dropped — a rule silently covering fewer kinds than the standard declares
// is a coverage claim nobody can check.
func LoadRules(path string) (cloud.TagRules, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return cloud.TagRules{}, nil, fmt.Errorf("read standard file %s: %w", path, err)
	}
	var sf standardFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return cloud.TagRules{}, nil, fmt.Errorf("parse standard file %s: %w", path, err)
	}
	if sf.Kind != standardKind {
		return cloud.TagRules{}, nil, fmt.Errorf("standard file %s: unexpected kind %q (want %s)", path, sf.Kind, standardKind)
	}

	keys := sf.Content.RequiredBySurface["aws"]
	if len(keys) == 0 {
		return cloud.TagRules{}, nil, fmt.Errorf("standard file %s: content.required_by_surface.aws is empty", path)
	}

	rules := cloud.TagRules{Required: keys}
	var unenforceable []string
	for _, c := range sf.Content.Conditional {
		if !strings.EqualFold(c.Surface, "aws") || c.Tag == "" {
			continue
		}
		var prefixes []string
		for _, kind := range c.RequiredOnKind {
			mapped, ok := awsKindPrefixes[kind]
			if !ok {
				unenforceable = append(unenforceable,
					fmt.Sprintf("%s is required on %s, which cloudgov does not enumerate", c.Tag, kind))
				continue
			}
			prefixes = append(prefixes, mapped...)
		}
		if len(prefixes) > 0 {
			rules.Conditional = append(rules.Conditional, cloud.ConditionalTag{Tag: c.Tag, Kinds: dedupe(prefixes)})
		}
	}
	return rules, unenforceable, nil
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

package output

import (
	"encoding/json"
	"io"

	"github.com/nanohype/cloudgov/internal/audit"
	"github.com/nanohype/cloudgov/internal/cloud"
)

// SARIF 2.1.0 structures (minimal subset for GitHub Advanced Security).
type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
	Kind    string       `json:"kind"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// WriteSARIF writes IAM findings in SARIF 2.1.0 format.
func WriteSARIF(w io.Writer, findings []cloud.Finding, version string) error {
	rules := buildRules()
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Detail},
			Kind:    "open",
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "cloudgov",
				Version:        version,
				InformationURI: "https://github.com/nanohype/cloudgov",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// WriteStorageSARIF writes storage audit findings in SARIF 2.1.0 format.
func WriteStorageSARIF(w io.Writer, findings []cloud.BucketFinding, version string) error {
	rules := buildStorageRules()
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Detail},
			Kind:    "open",
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "cloudgov",
				Version:        version,
				InformationURI: "https://github.com/nanohype/cloudgov",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// WriteSecretsSARIF writes secret findings in SARIF 2.1.0 format.
func WriteSecretsSARIF(w io.Writer, findings []cloud.SecretFinding, version string) error {
	rules := buildSecretsRules()
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Detail},
			Kind:    "open",
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "cloudgov",
				Version:        version,
				InformationURI: "https://github.com/nanohype/cloudgov",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifLevel(s cloud.Severity) string {
	switch s {
	case cloud.SeverityCritical, cloud.SeverityHigh:
		return "error"
	case cloud.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func buildStorageRules() []sarifRule {
	types := []struct {
		id    cloud.BucketFindingType
		name  string
		level string
	}{
		{cloud.BucketPublicAccess, "PublicAccess", "error"},
		{cloud.BucketUnencrypted, "Unencrypted", "error"},
		{cloud.BucketNoVersioning, "NoVersioning", "warning"},
		{cloud.BucketNoLogging, "NoLogging", "note"},
		{cloud.BucketPublicACL, "PublicACL", "error"},
	}
	var rules []sarifRule
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}

func buildSecretsRules() []sarifRule {
	types := []struct {
		id    cloud.SecretFindingType
		name  string
		level string
	}{
		{cloud.SecretAWSAccessKey, "AWSAccessKey", "error"},
		{cloud.SecretGCPServiceAccountKey, "GCPServiceAccountKey", "error"},
		{cloud.SecretPrivateKey, "PrivateKey", "error"},
		{cloud.SecretAzureConnectionString, "AzureConnectionString", "error"},
		{cloud.SecretPassword, "Password", "error"},
		{cloud.SecretAPIKey, "APIKey", "error"},
		{cloud.SecretBearerToken, "BearerToken", "error"},
		{cloud.SecretGenericSecret, "GenericSecret", "warning"},
	}
	var rules []sarifRule
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}

// WriteAuditSARIF writes all audit findings combined into a single SARIF 2.1.0 report.
func WriteAuditSARIF(w io.Writer, report *audit.Report, version string) error {
	var allRules []sarifRule
	allRules = append(allRules, buildRules()...)
	allRules = append(allRules, buildStorageRules()...)
	allRules = append(allRules, buildSecretsRules()...)
	allRules = append(allRules, buildNetworkRules()...)

	var results []sarifResult
	for _, f := range report.IAM {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: "[iam] " + f.Detail},
			Kind:    "open",
		})
	}
	for _, f := range report.Storage {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: "[storage] " + f.Detail},
			Kind:    "open",
		})
	}
	for _, f := range report.Network {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: "[network] " + f.Detail},
			Kind:    "open",
		})
	}
	for _, f := range report.Secrets {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: "[secrets] " + f.Detail},
			Kind:    "open",
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "cloudgov",
				Version:        version,
				InformationURI: "https://github.com/nanohype/cloudgov",
				Rules:          allRules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func buildNetworkRules() []sarifRule {
	types := []struct {
		id    cloud.NetworkFindingType
		name  string
		level string
	}{
		{cloud.NetworkOpenIngress, "OpenIngress", "error"},
		{cloud.NetworkOpenEgress, "OpenEgress", "warning"},
		{cloud.NetworkAdminPortOpen, "AdminPortOpen", "error"},
		{cloud.NetworkWideCIDR, "WideCIDR", "warning"},
	}
	var rules []sarifRule
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}

func buildRules() []sarifRule {
	types := []struct {
		id    cloud.FindingType
		name  string
		level string
	}{
		{cloud.FindingAdminAccess, "AdminAccess", "error"},
		{cloud.FindingWildcardResource, "WildcardResource", "error"},
		{cloud.FindingUnusedPermission, "UnusedPermission", "error"},
		{cloud.FindingCrossAccountAccess, "CrossAccountAccess", "error"},
		{cloud.FindingStalePrincipal, "StalePrincipal", "warning"},
		{cloud.FindingBroadScope, "BroadScope", "warning"},
		{cloud.FindingPublicAccess, "PublicAccess", "error"},
		{cloud.FindingUnencrypted, "Unencrypted", "error"},
		{cloud.FindingNoVersioning, "NoVersioning", "warning"},
		{cloud.FindingOrphanResource, "OrphanResource", "note"},
	}
	var rules []sarifRule
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}

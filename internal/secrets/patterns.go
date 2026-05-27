package secrets

import (
	"regexp"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// Pattern defines a regex-based secret detection rule.
type Pattern struct {
	Type     cloud.SecretFindingType
	Severity cloud.Severity
	Regex    *regexp.Regexp
	Name     string
}

// Patterns is the ordered list of secret detection patterns.
var Patterns = []Pattern{
	{
		Type:     cloud.SecretAWSAccessKey,
		Severity: cloud.SeverityCritical,
		Regex:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Name:     "AWS Access Key",
	},
	{
		Type:     cloud.SecretGCPServiceAccountKey,
		Severity: cloud.SeverityCritical,
		Regex:    regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		Name:     "GCP Service Account Key",
	},
	{
		Type:     cloud.SecretPrivateKey,
		Severity: cloud.SeverityCritical,
		Regex:    regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----`),
		Name:     "Private Key",
	},
	{
		Type:     cloud.SecretAzureConnectionString,
		Severity: cloud.SeverityCritical,
		Regex:    regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=`),
		Name:     "Azure Connection String",
	},
	{
		Type:     cloud.SecretPassword,
		Severity: cloud.SeverityHigh,
		Regex:    regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*\S+`),
		Name:     "Password",
	},
	{
		Type:     cloud.SecretAPIKey,
		Severity: cloud.SeverityHigh,
		Regex:    regexp.MustCompile(`(?i)(api[_\-]?key|apikey)\s*[=:]\s*\S+`),
		Name:     "API Key",
	},
	{
		Type:     cloud.SecretBearerToken,
		Severity: cloud.SeverityHigh,
		Regex:    regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`),
		Name:     "Bearer Token",
	},
	{
		Type:     cloud.SecretGenericSecret,
		Severity: cloud.SeverityMedium,
		Regex:    regexp.MustCompile(`(?i)(secret|token)\s*[=:]\s*\S{8,}`),
		Name:     "Generic Secret",
	},
}

// Match holds a single match from a secret detection pattern.
type Match struct {
	Type     cloud.SecretFindingType
	Severity cloud.Severity
	Name     string
	Value    string // raw matched text
}

// Scan checks a string against all secret patterns and returns matches.
func Scan(input string) []Match {
	var matches []Match
	for _, p := range Patterns {
		if loc := p.Regex.FindString(input); loc != "" {
			matches = append(matches, Match{
				Type:     p.Type,
				Severity: p.Severity,
				Name:     p.Name,
				Value:    loc,
			})
		}
	}
	return matches
}

// Redact returns a redacted version of a secret value: first 4 chars + "****".
func Redact(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:4] + "****"
}

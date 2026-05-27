package secrets

import (
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

func TestPatterns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantType cloud.SecretFindingType
		match    bool
	}{
		// AWS access key
		{name: "aws access key", input: "AKIAIOSFODNN7EXAMPLE", wantType: cloud.SecretAWSAccessKey, match: true},
		{name: "aws access key in env", input: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", wantType: cloud.SecretAWSAccessKey, match: true},
		{name: "not aws key short", input: "AKIA1234", match: false},

		// GCP service account
		{name: "gcp sa key json", input: `{"type": "service_account", "project_id": "my-project"}`, wantType: cloud.SecretGCPServiceAccountKey, match: true},
		{name: "gcp sa no space", input: `"type":"service_account"`, wantType: cloud.SecretGCPServiceAccountKey, match: true},
		{name: "not gcp sa", input: `"type": "user"`, match: false},

		// Private key
		{name: "rsa private key", input: "-----BEGIN RSA PRIVATE KEY-----", wantType: cloud.SecretPrivateKey, match: true},
		{name: "private key no rsa", input: "-----BEGIN PRIVATE KEY-----", wantType: cloud.SecretPrivateKey, match: true},
		{name: "public key no match", input: "-----BEGIN PUBLIC KEY-----", match: false},

		// Azure connection string
		{name: "azure conn string", input: "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123", wantType: cloud.SecretAzureConnectionString, match: true},
		{name: "not azure conn", input: "DefaultEndpointsProtocol=http;something", match: false},

		// Password
		{name: "password equals", input: "password=mysecretpass123", wantType: cloud.SecretPassword, match: true},
		{name: "PASSWORD colon", input: "PASSWORD: supersecret", wantType: cloud.SecretPassword, match: true},
		{name: "pwd equals", input: "pwd=abc123", wantType: cloud.SecretPassword, match: true},
		{name: "passwd equals", input: "passwd=hunter2", wantType: cloud.SecretPassword, match: true},
		{name: "password no value", input: "password=", match: false},

		// API key
		{name: "api_key equals", input: "api_key=abcdef123456", wantType: cloud.SecretAPIKey, match: true},
		{name: "api-key equals", input: "api-key=abcdef123456", wantType: cloud.SecretAPIKey, match: true},
		{name: "apikey colon", input: "apikey: mykey123", wantType: cloud.SecretAPIKey, match: true},

		// Bearer token
		{name: "bearer token", input: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJz", wantType: cloud.SecretBearerToken, match: true},
		{name: "bearer lowercase", input: "bearer abc123def456", wantType: cloud.SecretBearerToken, match: true},
		{name: "no bearer prefix", input: "abc123def456", match: false},

		// Generic secret
		{name: "secret equals long value", input: "secret=abcdefghijklmnop", wantType: cloud.SecretGenericSecret, match: true},
		{name: "token colon long value", input: "token: xyzabcde12345678", wantType: cloud.SecretGenericSecret, match: true},
		{name: "secret too short value", input: "secret=abc", match: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := Scan(tt.input)
			if tt.match {
				found := false
				for _, m := range matches {
					if m.Type == tt.wantType {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected match of type %s in %q, got %d matches: %v", tt.wantType, tt.input, len(matches), matches)
				}
			} else {
				if len(matches) > 0 {
					t.Errorf("expected no matches in %q, got %d: %v", tt.input, len(matches), matches)
				}
			}
		})
	}
}

func TestRedact(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"AKIAIOSFODNN7EXAMPLE", "AKIA****"},
		{"abc", "****"},
		{"", "****"},
		{"abcdef", "abcd****"},
	}
	for _, tt := range tests {
		got := Redact(tt.input)
		if got != tt.want {
			t.Errorf("Redact(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

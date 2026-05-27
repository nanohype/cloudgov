package cloud

import "context"

// SecretFindingType classifies the kind of leaked credential found.
type SecretFindingType string

const (
	SecretAWSAccessKey          SecretFindingType = "AWS_ACCESS_KEY"
	SecretGCPServiceAccountKey  SecretFindingType = "GCP_SERVICE_ACCOUNT_KEY"
	SecretPrivateKey            SecretFindingType = "PRIVATE_KEY"
	SecretAzureConnectionString SecretFindingType = "AZURE_CONNECTION_STRING"
	SecretPassword              SecretFindingType = "PASSWORD"
	SecretAPIKey                SecretFindingType = "API_KEY"
	SecretBearerToken           SecretFindingType = "BEARER_TOKEN"
	SecretGenericSecret         SecretFindingType = "GENERIC_SECRET"
)

// SecretFinding is a single leaked credential observation.
type SecretFinding struct {
	Severity     Severity
	Type         SecretFindingType
	Provider     string
	Resource     string // "lambda:my-function"
	ResourceType string // "lambda_env", "ecs_env", "ec2_userdata", "ssm_parameter"
	Region       string
	Key          string // env var name or config key where found
	Match        string // redacted: first 4 chars + "****"
	Detail       string
	Remediation  string
}

// SecretsProvider scans cloud resources for leaked credentials.
type SecretsProvider interface {
	Provider
	ScanSecrets(ctx context.Context) ([]SecretFinding, error)
}

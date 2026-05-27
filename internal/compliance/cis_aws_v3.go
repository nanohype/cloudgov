package compliance

import "github.com/nanohype/cloudgov/internal/cloud"

func cisAWSv3Benchmark() *Benchmark {
	return &Benchmark{
		ID:   "cis-aws-v3",
		Name: "CIS Amazon Web Services Foundations Benchmark v3.0",
		Controls: []Control{
			// 1 - Identity and Access Management
			{ID: "1.4", Title: "Ensure no root account access key exists", Section: "Identity and Access Management", Severity: cloud.SeverityCritical, Description: "The root account should not have access keys."},
			{ID: "1.5", Title: "Ensure MFA is enabled for the root account", Section: "Identity and Access Management", Severity: cloud.SeverityCritical, Description: "The root account should have MFA enabled."},
			{ID: "1.10", Title: "Ensure unused credentials are disabled", Section: "Identity and Access Management", Severity: cloud.SeverityMedium, Description: "Credentials not used in 90 days should be disabled."},
			{ID: "1.12", Title: "Ensure credentials unused for 45 days are disabled", Section: "Identity and Access Management", Severity: cloud.SeverityMedium, Description: "Credentials not used in 45 days or greater should be disabled."},
			{ID: "1.15", Title: "Ensure IAM Users receive permissions only through groups", Section: "Identity and Access Management", Severity: cloud.SeverityMedium, Description: "IAM users should not have inline or directly attached policies."},
			{ID: "1.16", Title: "Ensure IAM policies with full admin privileges are not attached", Section: "Identity and Access Management", Severity: cloud.SeverityCritical, Description: "No IAM policies should allow full *:* administrative privileges."},
			{ID: "1.17", Title: "Ensure a support role has been created for incident management", Section: "Identity and Access Management", Severity: cloud.SeverityLow, Description: "A support role should exist."},
			{ID: "1.19", Title: "Ensure IAM instance roles are used for resource access", Section: "Identity and Access Management", Severity: cloud.SeverityMedium, Description: "EC2 instances should use IAM roles for API access."},
			{ID: "1.22", Title: "Ensure access to AWSCloudShellFullAccess is restricted", Section: "Identity and Access Management", Severity: cloud.SeverityMedium, Description: "CloudShell full access should be restricted."},

			// 2 - Storage
			{ID: "2.1.1", Title: "Ensure S3 bucket policy is set to deny HTTP requests", Section: "Storage", Severity: cloud.SeverityMedium, Description: "S3 buckets should deny non-HTTPS requests."},
			{ID: "2.1.2", Title: "Ensure MFA Delete is enabled on S3 buckets", Section: "Storage", Severity: cloud.SeverityHigh, Description: "S3 buckets should have MFA Delete enabled."},
			{ID: "2.1.4", Title: "Ensure all data in S3 is encrypted", Section: "Storage", Severity: cloud.SeverityHigh, Description: "All S3 buckets should have default encryption enabled."},
			{ID: "2.1.5", Title: "Ensure S3 buckets are configured with Block Public Access", Section: "Storage", Severity: cloud.SeverityCritical, Description: "S3 buckets should have Block Public Access enabled."},
			{ID: "2.2.1", Title: "Ensure EBS volume encryption is enabled", Section: "Storage", Severity: cloud.SeverityHigh, Description: "EBS volumes should be encrypted."},

			// 3 - Logging
			{ID: "3.1", Title: "Ensure CloudTrail is enabled in all regions", Section: "Logging", Severity: cloud.SeverityHigh, Description: "CloudTrail should be enabled across all regions."},
			{ID: "3.4", Title: "Ensure CloudTrail log file validation is enabled", Section: "Logging", Severity: cloud.SeverityMedium, Description: "CloudTrail should have log file validation enabled."},
			{ID: "3.7", Title: "Ensure S3 bucket access logging is enabled on CloudTrail S3 bucket", Section: "Logging", Severity: cloud.SeverityMedium, Description: "CloudTrail S3 bucket should have access logging."},

			// 4 - Monitoring (tag-based checks)
			{ID: "4.1", Title: "Ensure appropriate tagging across all resources", Section: "Monitoring", Severity: cloud.SeverityLow, Description: "All resources should have required tags for tracking and compliance."},

			// 5 - Networking
			{ID: "5.1", Title: "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to admin ports", Section: "Networking", Severity: cloud.SeverityCritical, Description: "Security groups should not allow unrestricted access to admin ports (22, 3389)."},
			{ID: "5.2", Title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22", Section: "Networking", Severity: cloud.SeverityHigh, Description: "SSH should not be open to the world."},
			{ID: "5.3", Title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389", Section: "Networking", Severity: cloud.SeverityHigh, Description: "RDP should not be open to the world."},
			{ID: "5.4", Title: "Ensure the default security group of every VPC restricts all traffic", Section: "Networking", Severity: cloud.SeverityMedium, Description: "Default security groups should restrict all traffic."},
		},
	}
}

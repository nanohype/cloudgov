package compliance

import "github.com/nanohype/cloudgov/internal/cloud"

func cisAzureV2Benchmark() *Benchmark {
	return &Benchmark{
		ID:   "cis-azure-v2",
		Name: "CIS Microsoft Azure Foundations Benchmark v2.0",
		Controls: []Control{
			// 1 - Identity and Access Management
			{ID: "1.1.1", Title: "Ensure Security Defaults are enabled on Azure Active Directory", Section: "Identity and Access Management", Severity: cloud.SeverityCritical, Description: "Security Defaults provide baseline identity security for the organization."},
			{ID: "1.2.1", Title: "Ensure MFA is enabled for all users with write permissions", Section: "Identity and Access Management", Severity: cloud.SeverityCritical, Description: "Multi-factor authentication should be required for all users with write access."},
			{ID: "1.3.1", Title: "Ensure Guest Users are reviewed on a regular basis", Section: "Identity and Access Management", Severity: cloud.SeverityMedium, Description: "External guest accounts should be reviewed and removed when no longer needed."},

			// 2 - Microsoft Defender
			{ID: "2.1.1", Title: "Ensure that Microsoft Defender for Servers is set to On", Section: "Microsoft Defender", Severity: cloud.SeverityHigh, Description: "Enable Defender for Servers for threat detection."},

			// 3 - Storage Accounts
			{ID: "3.1", Title: "Ensure that Secure transfer required is set to Enabled", Section: "Storage Accounts", Severity: cloud.SeverityCritical, Description: "Storage accounts should require HTTPS for all requests."},
			{ID: "3.2", Title: "Ensure that storage account access keys are periodically regenerated", Section: "Storage Accounts", Severity: cloud.SeverityMedium, Description: "Rotate storage account access keys to reduce risk of compromised keys."},
			{ID: "3.7", Title: "Ensure that public access level is disabled for storage accounts with blob containers", Section: "Storage Accounts", Severity: cloud.SeverityCritical, Description: "Blob containers should not allow anonymous public read access."},
			{ID: "3.8", Title: "Ensure soft delete is enabled for Azure Storage", Section: "Storage Accounts", Severity: cloud.SeverityMedium, Description: "Soft delete protects against accidental or malicious deletion."},
			{ID: "3.15", Title: "Ensure storage accounts are encrypted with Customer-Managed Keys", Section: "Storage Accounts", Severity: cloud.SeverityMedium, Description: "Use CMK for storage encryption when required by policy."},

			// 4 - Database Services
			{ID: "4.1.1", Title: "Ensure that auditing is set to On for Azure SQL databases", Section: "Database Services", Severity: cloud.SeverityMedium, Description: "Enable auditing to track database events."},

			// 5 - Logging and Monitoring
			{ID: "5.1.2", Title: "Ensure Diagnostic Setting captures appropriate categories", Section: "Logging and Monitoring", Severity: cloud.SeverityHigh, Description: "Diagnostic Settings should capture Administrative, Security, ServiceHealth, and Alert logs."},

			// 6 - Networking
			{ID: "6.1", Title: "Ensure that RDP access from the internet is evaluated and restricted", Section: "Networking", Severity: cloud.SeverityCritical, Description: "NSG rules should not allow RDP (port 3389) from the internet."},
			{ID: "6.2", Title: "Ensure that SSH access from the internet is evaluated and restricted", Section: "Networking", Severity: cloud.SeverityCritical, Description: "NSG rules should not allow SSH (port 22) from the internet."},
			{ID: "6.4", Title: "Ensure that Network Security Group Flow Log retention period is greater than 90 days", Section: "Networking", Severity: cloud.SeverityMedium, Description: "NSG flow logs should be retained for at least 90 days."},

			// 7 - Virtual Machines
			{ID: "7.1", Title: "Ensure Virtual Machines are utilizing Managed Disks", Section: "Virtual Machines", Severity: cloud.SeverityHigh, Description: "Managed Disks provide better reliability and encryption support."},

			// 8 - Key Vault
			{ID: "8.1", Title: "Ensure that the expiration date is set on all keys", Section: "Key Vault", Severity: cloud.SeverityMedium, Description: "Key Vault keys should have an expiration date configured."},

			// 9 - AppService
			{ID: "9.1", Title: "Ensure App Service Authentication is set up for apps in Azure App Service", Section: "AppService", Severity: cloud.SeverityMedium, Description: "App Service apps should require authentication."},
			{ID: "9.10", Title: "Ensure that Azure Active Directory Authentication is configured for App Service", Section: "AppService", Severity: cloud.SeverityMedium, Description: "Use Azure AD for App Service authentication."},
		},
	}
}

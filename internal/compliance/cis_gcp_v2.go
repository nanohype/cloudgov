package compliance

import "github.com/stxkxs/matlock/internal/cloud"

func cisGCPv2Benchmark() *Benchmark {
	return &Benchmark{
		ID:   "cis-gcp-v2",
		Name: "CIS Google Cloud Platform Foundation Benchmark v2.0",
		Controls: []Control{
			// 1 - Identity and Access Management
			{ID: "1.1", Title: "Ensure that corporate login credentials are used", Section: "Identity and Access Management", Severity: cloud.SeverityHigh, Description: "Use corporate credentials instead of personal Gmail accounts for GCP access."},
			{ID: "1.4", Title: "Ensure that service accounts do not have admin privileges", Section: "Identity and Access Management", Severity: cloud.SeverityCritical, Description: "Service accounts should not be granted Owner, Editor, or other admin roles."},
			{ID: "1.5", Title: "Ensure that service accounts do not have organization-level roles", Section: "Identity and Access Management", Severity: cloud.SeverityCritical, Description: "Service accounts should be scoped to projects, not organizations."},
			{ID: "1.6", Title: "Ensure that user-managed service account keys are rotated within 90 days", Section: "Identity and Access Management", Severity: cloud.SeverityMedium, Description: "Service account keys should be rotated regularly."},
			{ID: "1.7", Title: "Ensure user-managed service account keys are not created for a project", Section: "Identity and Access Management", Severity: cloud.SeverityMedium, Description: "Prefer Workload Identity or attached service accounts over user-managed keys."},

			// 2 - Logging and Monitoring
			{ID: "2.1", Title: "Ensure Cloud Audit Logging is configured properly for all services", Section: "Logging and Monitoring", Severity: cloud.SeverityHigh, Description: "Enable Data Access audit logs for all services."},
			{ID: "2.2", Title: "Ensure that sinks are configured for all log entries", Section: "Logging and Monitoring", Severity: cloud.SeverityMedium, Description: "Export logs to Cloud Storage, BigQuery, or Pub/Sub for long-term retention."},

			// 3 - Networking
			{ID: "3.1", Title: "Ensure default firewall rules do not allow unrestricted ingress from 0.0.0.0/0", Section: "Networking", Severity: cloud.SeverityCritical, Description: "Default network firewall rules should not allow all traffic from the internet."},
			{ID: "3.6", Title: "Ensure SSH access is restricted from the internet", Section: "Networking", Severity: cloud.SeverityHigh, Description: "Firewall rules should not allow SSH (port 22) from 0.0.0.0/0."},
			{ID: "3.7", Title: "Ensure RDP access is restricted from the internet", Section: "Networking", Severity: cloud.SeverityHigh, Description: "Firewall rules should not allow RDP (port 3389) from 0.0.0.0/0."},

			// 4 - Virtual Machines
			{ID: "4.1", Title: "Ensure that instances are not configured to use default service accounts with full API access", Section: "Virtual Machines", Severity: cloud.SeverityMedium, Description: "Compute instances should use custom service accounts with minimal scopes."},
			{ID: "4.6", Title: "Ensure VM disks for critical VMs are encrypted with Customer-Managed Encryption Keys", Section: "Virtual Machines", Severity: cloud.SeverityMedium, Description: "Use CMEK for disk encryption on sensitive workloads."},

			// 5 - Storage
			{ID: "5.1", Title: "Ensure that Cloud Storage bucket is not anonymously or publicly accessible", Section: "Storage", Severity: cloud.SeverityCritical, Description: "Buckets should not grant allUsers or allAuthenticatedUsers access."},
			{ID: "5.2", Title: "Ensure that Cloud Storage buckets have uniform bucket-level access enabled", Section: "Storage", Severity: cloud.SeverityMedium, Description: "Use uniform bucket-level access instead of fine-grained ACLs."},

			// 6 - Cloud SQL
			{ID: "6.1.1", Title: "Ensure that Cloud SQL database instances are not open to the world", Section: "Cloud SQL", Severity: cloud.SeverityCritical, Description: "Cloud SQL instances should not have 0.0.0.0/0 in authorized networks."},
			{ID: "6.2.1", Title: "Ensure that Cloud SQL database instances are encrypted with Customer-Managed Encryption Keys", Section: "Cloud SQL", Severity: cloud.SeverityMedium, Description: "Use CMEK for Cloud SQL encryption."},

			// 7 - Pub/Sub
			{ID: "7.1", Title: "Ensure that Pub/Sub topics are encrypted with Customer-Managed Encryption Keys", Section: "Pub/Sub", Severity: cloud.SeverityMedium, Description: "Use CMEK for Pub/Sub topic encryption."},
		},
	}
}

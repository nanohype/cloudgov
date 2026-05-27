package compliance

import "github.com/nanohype/cloudgov/internal/cloud"

func soc2TypeIIBenchmark() *Benchmark {
	return &Benchmark{
		ID:   "soc2",
		Name: "SOC 2 Type II — Trust Services Criteria",
		Controls: []Control{
			// CC1 — Control Environment
			{ID: "CC1.1", Title: "COSO Principle 1: The entity demonstrates a commitment to integrity and ethical values", Section: "Control Environment", Severity: cloud.SeverityMedium, Description: "Requires organizational policy review — not evaluatable from cloud API data."},

			// CC2 — Communication and Information
			{ID: "CC2.1", Title: "COSO Principle 13: The entity obtains or generates relevant, quality information", Section: "Communication and Information", Severity: cloud.SeverityLow, Description: "Requires policy and communication review — not evaluatable from cloud API data."},

			// CC3 — Risk Assessment
			{ID: "CC3.1", Title: "COSO Principle 6: The entity specifies objectives with sufficient clarity to identify risks", Section: "Risk Assessment", Severity: cloud.SeverityMedium, Description: "Requires risk assessment process review — not evaluatable from cloud API data."},

			// CC4 — Monitoring Activities
			{ID: "CC4.1", Title: "COSO Principle 16: The entity selects, develops, and performs ongoing evaluations", Section: "Monitoring Activities", Severity: cloud.SeverityMedium, Description: "Requires process-level monitoring review — not evaluatable from cloud API data."},

			// CC5 — Control Activities
			{ID: "CC5.1", Title: "COSO Principle 10: The entity selects and develops control activities", Section: "Control Activities", Severity: cloud.SeverityMedium, Description: "Requires organizational control activity review — not evaluatable from cloud API data."},

			// CC6 — Logical and Physical Access Controls
			{ID: "CC6.1", Title: "Logical access security over protected information assets", Section: "Logical and Physical Access", Severity: cloud.SeverityCritical, Description: "IAM policies should enforce least privilege. Evaluated via admin access findings."},
			{ID: "CC6.2", Title: "New logical access is provisioned and approved through a controlled process", Section: "Logical and Physical Access", Severity: cloud.SeverityHigh, Description: "Stale or unused credentials indicate inadequate access lifecycle. Evaluated via unused credential findings."},
			{ID: "CC6.3", Title: "Role-based access controls enforce least privilege", Section: "Logical and Physical Access", Severity: cloud.SeverityHigh, Description: "Broad-scope and wildcard permissions violate least privilege. Evaluated via IAM broad scope findings."},
			{ID: "CC6.6", Title: "Logical access security measures against threats from outside system boundaries", Section: "Logical and Physical Access", Severity: cloud.SeverityCritical, Description: "Admin ports open to the internet represent external threat surface. Evaluated via network findings."},
			{ID: "CC6.7", Title: "Encryption of data in transit and at rest", Section: "Logical and Physical Access", Severity: cloud.SeverityHigh, Description: "Unencrypted storage violates data protection requirements. Evaluated via storage encryption findings."},

			// CC7 — System Operations
			{ID: "CC7.1", Title: "Configuration and change management monitoring", Section: "System Operations", Severity: cloud.SeverityMedium, Description: "IAM configuration should be monitored for unauthorized changes. Evaluated via IAM findings."},
			{ID: "CC7.2", Title: "Security event monitoring and anomaly detection", Section: "System Operations", Severity: cloud.SeverityMedium, Description: "Logging gaps prevent security event detection. Evaluated via access logging findings."},

			// CC8 — Change Management
			{ID: "CC8.1", Title: "Changes to infrastructure and software are authorized and managed", Section: "Change Management", Severity: cloud.SeverityMedium, Description: "Requires ITSM and change management process review — not evaluatable from cloud API data."},

			// CC9 — Risk Mitigation
			{ID: "CC9.1", Title: "The entity identifies, selects, and develops risk mitigation activities", Section: "Risk Mitigation", Severity: cloud.SeverityMedium, Description: "Requires vendor and contract scope review — not evaluatable from cloud API data."},

			// A1 — Availability
			{ID: "A1.2", Title: "Environmental protections and recovery infrastructure", Section: "Availability", Severity: cloud.SeverityHigh, Description: "Expired or critically expiring certificates threaten service availability. Evaluated via cert expiry findings."},

			// C1 — Confidentiality
			{ID: "C1.1", Title: "Confidential information is identified and protected from unauthorized access", Section: "Confidentiality", Severity: cloud.SeverityCritical, Description: "Publicly accessible storage exposes confidential data. Evaluated via public access findings."},
			{ID: "C1.2", Title: "Confidential information is disposed of or encrypted as required", Section: "Confidentiality", Severity: cloud.SeverityCritical, Description: "Unencrypted storage violates confidentiality requirements. Evaluated via storage encryption findings."},

			// P6 — Privacy
			{ID: "P6.1", Title: "Personal information is protected against unauthorized access", Section: "Privacy", Severity: cloud.SeverityHigh, Description: "Public ACLs on storage may expose personal data. Evaluated via public ACL findings."},
		},
	}
}

# matlock

Multi-cloud security and cost swiss army knife — single binary, zero dependencies.

Audit IAM permissions, spot cost anomalies, find orphaned resources, flag insecure storage, detect overly permissive firewall rules, monitor TLS certificate expiry, enforce resource tagging, check service quota utilization, save and compare scan baselines, generate HTML reports, and more — across AWS, GCP, and Azure.

<!-- screenshot placeholder -->
<!-- ![matlock iam scan output](docs/screenshots/iam-scan.png) -->

---

## Installation

### Homebrew (macOS / Linux)

```sh
brew install stxkxs/tap/matlock
```

### go install

```sh
go install github.com/stxkxs/matlock@latest
```

### Direct download

Pre-built binaries for Linux, macOS, and Windows are attached to every [GitHub release](https://github.com/stxkxs/matlock/releases).

```sh
# macOS arm64 example
curl -sSL https://github.com/stxkxs/matlock/releases/latest/download/matlock_Darwin_arm64.tar.gz \
  | tar -xz matlock
sudo mv matlock /usr/local/bin/
```

Verify the download against the published SHA256 checksums:

```sh
curl -sSL https://github.com/stxkxs/matlock/releases/latest/download/checksums.txt | sha256sum --check --ignore-missing
```

### Build from source

Requires Go 1.26+ and [Task](https://taskfile.dev).

```sh
git clone https://github.com/stxkxs/matlock.git
cd matlock
task build
```

---

## Credentials setup

matlock auto-detects available providers from environment variables and credential files. You only need to configure the providers you actually use.

### AWS

matlock uses the standard AWS SDK credential chain.

```sh
# Option 1 — environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1

# Option 2 — named profile
export AWS_PROFILE=my-profile
export AWS_REGION=us-east-1

# Option 3 — IAM role / instance metadata (no env vars needed)
```

Required IAM permissions for a read-only audit role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:List*",
        "iam:Get*",
        "cloudtrail:LookupEvents",
        "ce:GetCostAndUsage",
        "ec2:Describe*",
        "elasticloadbalancing:Describe*",
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "rds:DescribeDBInstances",
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "lambda:ListTags",
        "lambda:GetAccountSettings",
        "iam:GetAccountSummary",
        "servicequotas:GetServiceQuota",
        "servicequotas:ListServiceQuotas"
      ],
      "Resource": "*"
    }
  ]
}
```

### GCP

```sh
# Option 1 — application default credentials (gcloud)
gcloud auth application-default login

# Option 2 — service account key
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
export GOOGLE_CLOUD_PROJECT=my-project-id

# Required for cost diff
export GOOGLE_BILLING_ACCOUNT_ID=XXXXXX-XXXXXX-XXXXXX
```

Required IAM roles for the service account:
- `roles/iam.securityReviewer`
- `roles/logging.viewer`
- `roles/billing.viewer`
- `roles/storage.objectViewer`
- `roles/compute.viewer`
- `roles/certificatemanager.viewer` (for `matlock certs`)
- `compute.projects.get` permission (for `matlock quota`)

### Azure

```sh
# Option 1 — Azure CLI
az login
export AZURE_SUBSCRIPTION_ID=...

# Option 2 — service principal
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_SUBSCRIPTION_ID=...
```

Required role assignments:
- `Reader` on the subscription
- `Cost Management Reader` on the subscription
- `Key Vault Reader` + `Key Vault Certificates Officer` (or `Key Vault Reader` if using RBAC-enabled vaults) for `matlock certs`

---

## Commands

### `matlock iam scan` — unused and overprivileged IAM

Compares granted permissions against CloudTrail / Audit Log activity over the lookback window and reports unused, admin, and cross-account risks.

```sh
# Scan all auto-detected providers (90-day lookback)
matlock iam scan

# AWS only, last 30 days, show CRITICAL and HIGH only
matlock iam scan --provider aws --days 30 --severity HIGH

# Scan a specific principal
matlock iam scan --provider gcp --principal serviceAccount:scanner@my-project.iam.gserviceaccount.com

# JSON output for downstream tooling
matlock iam scan --output json --output-file report.json

# SARIF output for GitHub Advanced Security
matlock iam scan --output sarif --output-file results.sarif

# Increase parallelism for large accounts
matlock iam scan --concurrency 20
```

<!-- screenshot placeholder -->
<!-- ![iam scan table output](docs/screenshots/iam-scan.png) -->

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan: `aws`, `gcp`, `azure` |
| `--days` | `90` | Audit log lookback window in days |
| `--principal` | | Scan a single principal by name or ID |
| `--severity` | `LOW` | Minimum severity to report: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `--output` | `table` | Output format: `table`, `json`, `sarif` |
| `--output-file` | | Write output to file instead of stdout |
| `--concurrency` | `10` | Maximum parallel goroutines per provider |
| `--profile` | | AWS named profile to use for credentials |

---

### `matlock iam fix` — generate Terraform remediations

Reads a JSON scan report and generates least-privilege Terraform policy files for each flagged principal.

```sh
# Generate fixes for all HIGH+ findings
matlock iam fix --from report.json

# Write fixes to a custom directory
matlock iam fix --from report.json --out ./tf-fixes

# Include MEDIUM severity fixes too
matlock iam fix --from report.json --severity MEDIUM
```

**Workflow**

```sh
matlock iam scan --output json --output-file report.json
matlock iam fix --from report.json --out ./fixes
ls ./fixes/
# minimal_lambda_executor.tf
# minimal_my_project_scanner_at_my_project_iam_gserviceaccount_com.tf
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--from` | (required) | Path to JSON report from `matlock iam scan --output json` |
| `--format` | `terraform` | Output format: `terraform`, `json` |
| `--out` | `./matlock-fixes` | Output directory for generated files |
| `--severity` | `HIGH` | Minimum severity to generate fixes for |

---

### `matlock cost diff` — spend delta between time windows

Compares cloud spend between the last N days and the N days before that, surfacing unexpected increases service by service.

```sh
# Compare last 30 days vs the 30 days before
matlock cost diff

# 7-day comparison, AWS only
matlock cost diff --provider aws --days 7

# JSON output for alerting pipelines
matlock cost diff --output json
```

<!-- screenshot placeholder -->
<!-- ![cost diff table output](docs/screenshots/cost-diff.png) -->

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to query |
| `--days` | `30` | Compare last N days vs N days before |
| `--threshold` | `0` | Only show services with >N% change (e.g. `--threshold 20`) |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

Cost increases >10% are shown in red; decreases are shown in green.

---

### `matlock orphans` — unused disks, IPs, and load balancers

Finds unattached disks, reserved IPs with no instance, and idle load balancers. Reports estimated monthly cost.

```sh
# All providers
matlock orphans

# Only report resources costing more than $5/month
matlock orphans --min-cost 5

# JSON for Slack/PagerDuty integration
matlock orphans --output json
```

<!-- screenshot placeholder -->
<!-- ![orphans table output](docs/screenshots/orphans.png) -->

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan |
| `--min-cost` | `0` | Only report orphans with monthly cost above this USD threshold |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

The table includes a TOTAL row summing all monthly costs.

---

### `matlock storage audit` — public buckets and encryption gaps

Audits object storage for public access, missing encryption, disabled versioning, and missing access logging.

```sh
# All providers
matlock storage audit

# HIGH and CRITICAL findings only
matlock storage audit --severity HIGH

# JSON for SIEM ingestion
matlock storage audit --output json --output-file storage-findings.json
```

<!-- screenshot placeholder -->
<!-- ![storage audit table output](docs/screenshots/storage-audit.png) -->

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan |
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `matlock network audit` — overly permissive firewall rules

Checks security groups (AWS), firewall rules (GCP), and network security groups (Azure) for rules that expose sensitive ports to the internet.

Severity rules:
- **CRITICAL** — `0.0.0.0/0` on SSH (22), RDP (3389), or database ports (3306, 5432, 1433, 27017, 6379, 9200)
- **HIGH** — `0.0.0.0/0` on any non-HTTP/HTTPS port
- **MEDIUM** — unrestricted egress (all traffic to `0.0.0.0/0`)

```sh
# All providers
matlock network audit

# AWS only, show CRITICAL findings
matlock network audit --provider aws --severity CRITICAL

# JSON output
matlock network audit --output json --output-file network-findings.json

# Generate shell remediation scripts (one per provider) alongside the table
matlock network audit --fix --out fixes/
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan |
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |
| `--fix` | `false` | Generate shell remediation scripts for each finding |
| `--out` | `.` | Directory to write fix scripts (used with `--fix`) |

---

### `matlock remediate` — generate fix scripts from a saved scan report

Read a previously-saved JSON scan report and emit shell scripts that remediate each finding. The offline equivalent of `<domain> audit --fix` — useful when you want to review findings first, gate remediation behind code review, or apply a subset by severity.

Supported report types: `storage`, `network`. Reports are read from files written via `--output json --output-file <path>` on the corresponding scan command.

```sh
# Generate fix scripts from a saved storage scan
matlock storage audit --output json --output-file storage.json
matlock remediate --type storage --from storage.json --out fixes/

# Same for network, only CRITICAL findings
matlock network audit --output json --output-file network.json
matlock remediate --type network --from network.json --severity CRITICAL --out fixes/
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--type` | (required) | Report type: `storage` or `network` |
| `--from` | (required) | Path to JSON scan report |
| `--out` | `.` | Directory to write fix scripts |
| `--severity` | `LOW` | Minimum severity to include in fix scripts |

---

### `matlock certs` — TLS certificate expiry

Lists TLS certificates from ACM (AWS), Certificate Manager (GCP), and Azure Key Vault that are expired or expiring soon.

Severity rules:
- **CRITICAL** — expired, or expiring within 7 days
- **HIGH** — expiring within 30 days
- **MEDIUM** — expiring within 60 days
- **LOW** — expiring within 90 days (default `--days` threshold)

```sh
# All providers, warn on certs expiring within 90 days (default)
matlock certs

# Only show certs expiring within 30 days
matlock certs --days 30

# AWS only, CRITICAL and HIGH only
matlock certs --provider aws --severity HIGH

# JSON output
matlock certs --output json --output-file certs.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan |
| `--days` | `90` | Include certs expiring within this many days |
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

> **GCP note:** Certificate Manager must be enabled in your project (`gcloud services enable certificatemanager.googleapis.com`). If the API is not enabled, `matlock certs` skips GCP with a warning.

---

### `matlock tags` — missing resource tags/labels

Audits EC2 instances, S3 buckets, RDS databases, Lambda functions (AWS), compute instances and GCS buckets (GCP), and all resource types (Azure) for missing required tags or labels.

All findings are **MEDIUM** severity.

```sh
# Require owner, env, and cost-center tags across all providers
matlock tags --require owner,env,cost-center

# AWS only
matlock tags --provider aws --require owner,env

# JSON output
matlock tags --require owner,env --output json --output-file tags.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan |
| `--require` | (required) | Comma-separated tag/label keys that must be present |
| `--severity` | `MEDIUM` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `matlock lambda audit` — Lambda resource-policy exposure (AWS)

Inspects each AWS Lambda function's resource-based policy (`lambda:GetPolicy`) for patterns that grant invoke permission too widely. This is the *resource-based* counterpart to `matlock iam scan` — that one checks what identities can do *from* the inside; this one checks who can invoke *into* the function from the outside.

Severity rules:
- **CRITICAL** — `Principal: "*"` or `Principal: {"AWS": "*"}` (anyone can invoke)
- **HIGH** — cross-account principal in `Principal: {"AWS": "arn:..."}` (a different account is allowed to invoke)
- **HIGH** — `Principal: {"Service": "..."}` without `aws:SourceAccount` or `aws:SourceArn` condition (confused-deputy risk)
- **HIGH** — `Action: "*"` or `Action: "lambda:*"` in any allow statement

Functions without a resource policy are silently skipped — they're only reachable via identity-based IAM, which the IAM scan already covers.

```sh
# Audit all Lambda resource policies in the current AWS account
matlock lambda audit

# CRITICAL only, JSON output
matlock lambda audit --severity CRITICAL --output json --output-file lambda.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | `aws` | Currently only `aws` is supported |
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `matlock k8s rbac` — over-privileged Kubernetes RBAC

Scans cluster-scoped ClusterRoles and ClusterRoleBindings for the patterns that produce real incidents: wildcard verbs/resources, dangerous verbs (create/update/patch/delete) on wildcard resources, and bindings to broad subject groups (`system:authenticated`, `system:unauthenticated`, `system:masters`). Built-in default roles (`cluster-admin`, `admin`, `edit`, `view`, `system:*`, `kubeadm:*`) are skipped so the output focuses on user-introduced risk.

Connection uses the standard kubeconfig chain: `--kubeconfig` flag → `$KUBECONFIG` → `~/.kube/config` → in-cluster service-account token.

```sh
# Scan the cluster of the current kubeconfig context
matlock k8s rbac

# Use a specific kubeconfig
matlock k8s rbac --kubeconfig /path/to/kubeconfig

# JSON output for CI
matlock k8s rbac --output json --output-file rbac.json

# HIGH and above only
matlock k8s rbac --severity HIGH
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--kubeconfig` | (chain) | Path to kubeconfig file |
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `matlock secrets scan` — leaked credentials in cloud resources

Scans Lambda environment variables, ECS task definitions, EC2 user data (AWS), Cloud Functions environment, App Service settings (Azure), and similar runtime configuration for embedded secrets — AWS keys, Slack tokens, private keys, GitHub tokens, generic high-entropy strings.

```sh
# Scan all auto-detected providers
matlock secrets scan

# AWS only, HIGH and above
matlock secrets scan --provider aws --severity HIGH

# SARIF output for GitHub Advanced Security
matlock secrets scan --output sarif --output-file secrets.sarif
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan: `aws`, `gcp`, `azure` |
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json`, `sarif` |
| `--output-file` | | Write output to file instead of stdout |

---

### `matlock compliance <benchmark>` — map findings to compliance controls

Loads JSON scan reports from prior matlock runs and maps the findings to controls in a named benchmark, producing a pass/fail evaluation per control.

Available benchmarks: `cis-aws-v3`, `cis-gcp-v2`, `cis-azure-v2`, `soc2`.

```sh
# Produce JSON reports first
matlock iam scan --output json --output-file iam.json
matlock storage audit --output json --output-file storage.json

# Then evaluate against a benchmark
matlock compliance cis-aws-v3 --iam-report iam.json --storage-report storage.json

# JSON output for ingest into a dashboard
matlock compliance soc2 --iam-report iam.json --output json --output-file soc2.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--iam-report` | | Path to JSON report from `iam scan` |
| `--storage-report` | | Path to JSON report from `storage audit` |
| `--network-report` | | Path to JSON report from `network audit` |
| `--certs-report` | | Path to JSON report from `certs` |
| `--tags-report` | | Path to JSON report from `tags` |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `matlock drift <tfstate>` — Terraform state vs live cloud

Reads a `terraform.tfstate` file and checks each managed resource against the cloud API to detect modifications or deletions outside Terraform. Supports AWS security groups / IAM policies / S3 buckets, GCP firewalls / storage buckets, Azure NSGs / storage accounts.

```sh
# Local state file
matlock drift terraform.tfstate

# Filter to a single resource type
matlock drift terraform.tfstate --resource-type aws_security_group

# Limit to a specific provider, lower concurrency
matlock drift terraform.tfstate --provider aws --concurrency 5

# JSON output
matlock drift terraform.tfstate --output json --output-file drift.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto from state | Cloud providers to query: `aws`, `gcp`, `azure` |
| `--resource-type` | | Filter to a single Terraform resource type |
| `--concurrency` | `10` | Max concurrent API calls |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `matlock audit` — unified full-spectrum audit

Runs all security and cost scans (IAM, storage, network, orphans, certs, tags, secrets) in one shot and produces a single combined report. Skip specific domains with `--skip`.

```sh
# Full audit across all auto-detected providers
matlock audit

# Skip IAM and certs domains
matlock audit --skip iam,certs

# HIGH and CRITICAL findings only, JSON output
matlock audit --severity HIGH --output json --output-file audit.json

# SARIF output for GitHub Advanced Security
matlock audit --output sarif --output-file audit.sarif

# AWS only with custom thresholds
matlock audit --provider aws --iam-days 30 --cert-days 60 --require-tags owner,env
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan: `aws`, `gcp`, `azure` |
| `--skip` | | Domains to skip: `iam`, `storage`, `network`, `orphans`, `certs`, `tags`, `secrets` |
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json`, `sarif` |
| `--output-file` | | Write output to file instead of stdout |
| `--iam-days` | `90` | IAM audit log lookback period in days |
| `--cert-days` | `90` | Certificate expiry warning threshold in days |
| `--require-tags` | | Required tags for tag audit (comma-separated) |
| `--concurrency` | `10` | Max parallel goroutines for IAM scanning |
| `--sink` | | Notification sink (repeatable). See **Notification sinks** below. |
| `--report-url` | | URL embedded in sink notifications (link to full report) |

#### Notification sinks

`matlock audit --sink <spec>` posts a digest of the run to an external system after the scan completes. Sinks fire on a best-effort basis — one bad sink does not block the others, and audit exit code is unaffected. The flag is repeatable, so you can deliver to several destinations at once.

| Spec form | What it does |
|---|---|
| `slack:<webhook-url>` | Block Kit message with severity-coded header, per-domain summary, top 10 findings, and optional report link |
| `webhook:<url>` | POSTs the raw JSON digest to any URL; receivers parse it however they like |
| `pagerduty:<routing-key>` | PagerDuty Events API v2 trigger — only fires when the digest contains at least one critical or high finding (avoids alert fatigue) |

```sh
# Post a Slack notification on every audit run
matlock audit --sink slack:https://hooks.slack.com/services/T00/B00/XXX

# Page on-call AND notify Slack AND forward to a custom collector
matlock audit \
  --sink slack:https://hooks.slack.com/services/T00/B00/XXX \
  --sink pagerduty:my-pd-routing-key \
  --sink webhook:https://collector.example.com/matlock \
  --report-url https://reports.example.com/audit-$(date +%F).html
```

---

### `matlock inventory` — list all cloud resources

Lists all cloud resources across providers with type, region, tags, and creation date. Groups by type and region for a complete asset overview.

```sh
# List all resources across auto-detected providers
matlock inventory

# Filter to specific resource types
matlock inventory --type ec2,s3,lambda

# AWS only, JSON output
matlock inventory --provider aws --output json --output-file inventory.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to list: `aws`, `gcp`, `azure` |
| `--type` | all | Resource types to list (e.g. `ec2`, `s3`, `lambda`) |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `matlock quota` — service quota utilization

Checks service quota usage across cloud providers to prevent outages from silently hitting limits. Reports IAM, EC2, S3, Lambda, RDS quotas (AWS), compute project quotas (GCP), and compute/network/storage quotas (Azure).

```sh
# All providers, all quotas
matlock quota

# Only quotas above 50% utilization
matlock quota --threshold 50

# AWS only, JSON output
matlock quota --provider aws --output json --output-file quotas.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to check: `aws`, `gcp`, `azure` |
| `--threshold` | `0` | Minimum utilization percentage to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

Utilization is color-coded: green (<50%), yellow (50-80%), red (>80%).

---

### `matlock baseline` — save and manage scan baselines

Save any scan report as a named baseline for later comparison with `matlock compare`.

```sh
# Save a baseline from a scan report
matlock iam scan --output json --output-file scan.json
matlock baseline save --from scan.json --name pre-deploy

# List saved baselines
matlock baseline list

# Delete a baseline
matlock baseline delete --name old-scan
```

Baselines are stored in `~/.matlock/baselines/`.

**Subcommands**

| Subcommand | Description |
|------------|-------------|
| `baseline save --from <file> --name <name>` | Save a report as a named baseline |
| `baseline list` | List all saved baselines with dates |
| `baseline delete --name <name>` | Delete a saved baseline |

---

### `matlock compare` — diff two scan reports

Compares two scan reports (or a saved baseline against a current report) and classifies each finding as new, resolved, or unchanged.

```sh
# Compare a saved baseline against a new scan
matlock compare --baseline pre-deploy --current scan-after.json

# Compare two report files directly
matlock compare --from old-report.json --to new-report.json

# JSON output
matlock compare --from old.json --to new.json --output json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--baseline` | | Name of saved baseline to compare against |
| `--current` | | Path to current report JSON file |
| `--from` | | Path to older report JSON file |
| `--to` | | Path to newer report JSON file |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

Use `--baseline` + `--current` or `--from` + `--to` (not both). Supports all report types: audit, IAM, storage, network, orphans, certs, tags, secrets, quotas.

**End-to-end workflow**

```sh
# Before a deploy: scan and save a baseline
matlock audit --output json --output-file audit.json
matlock baseline save --from audit.json --name pre-deploy-v2

# After the deploy: scan again and compare
matlock audit --output json --output-file audit-after.json
matlock compare --baseline pre-deploy-v2 --current audit-after.json

# Output shows:
#   +NEW        findings introduced since the baseline
#   -RESOLVED   findings that no longer appear
#   =UNCHANGED  findings present in both
```

You can also skip baselines and compare any two JSON files directly:

```sh
matlock compare --from monday-scan.json --to friday-scan.json --output json
```

---

### `matlock report` — generate HTML executive summary

Generates a standalone, self-contained HTML report from any JSON scan output. Includes summary cards, severity breakdown, domain-specific tables, and client-side table sorting. Supports light and dark mode via `prefers-color-scheme`.

```sh
# Generate from an audit report
matlock audit --output json --output-file audit.json
matlock report --from audit.json --out report.html --open

# Generate from any scan report
matlock report --from iam-scan.json --out iam-report.html

# Explicit type override
matlock report --from data.json --type orphans --out orphans.html
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--from` | (required) | Path to scan report JSON file |
| `--out` | `report.html` | Output HTML file path |
| `--type` | `auto` | Report type: `auto`, `audit`, `iam`, `storage`, `network`, `orphans`, `certs`, `tags`, `secrets`, `cost`, `quotas` |
| `--open` | `false` | Open the report in the default browser after generation |

---

## Global flags

| Flag | Description |
|------|-------------|
| `--quiet`, `-q` | Suppress all progress and summary output on stderr (for scripts) |
| `--version` | Print version, commit hash, and build date |

---

## CI usage

### GitHub Actions — SARIF upload

Upload IAM findings to GitHub Advanced Security (requires `security-events: write` permission):

```yaml
name: matlock security scan

on:
  schedule:
    - cron: '0 6 * * 1'   # every Monday at 06:00 UTC
  workflow_dispatch:

permissions:
  security-events: write

jobs:
  iam-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install matlock
        run: |
          curl -sSL https://github.com/stxkxs/matlock/releases/latest/download/matlock_Linux_amd64.tar.gz \
            | tar -xz matlock
          sudo mv matlock /usr/local/bin/

      - name: Run IAM scan
        env:
          AWS_ROLE_ARN: ${{ secrets.MATLOCK_ROLE_ARN }}
          AWS_REGION: us-east-1
        run: |
          matlock iam scan \
            --provider aws \
            --severity HIGH \
            --output sarif \
            --output-file results.sarif \
            --quiet

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitHub Actions — full audit

Run a unified audit across all domains in CI:

```yaml
name: matlock full audit

on:
  schedule:
    - cron: '0 6 * * 1'
  workflow_dispatch:

permissions:
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install matlock
        run: |
          curl -sSL https://github.com/stxkxs/matlock/releases/latest/download/matlock_Linux_amd64.tar.gz \
            | tar -xz matlock
          sudo mv matlock /usr/local/bin/

      - name: Run full audit
        env:
          AWS_ROLE_ARN: ${{ secrets.MATLOCK_ROLE_ARN }}
          AWS_REGION: us-east-1
        run: |
          matlock audit \
            --provider aws \
            --severity HIGH \
            --output sarif \
            --output-file audit.sarif \
            --quiet

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: audit.sarif
```

### GitLab CI — JSON report artifact

```yaml
matlock:
  image: ubuntu:24.04
  before_script:
    - curl -sSL https://github.com/stxkxs/matlock/releases/latest/download/matlock_Linux_amd64.tar.gz
        | tar -xz matlock
    - mv matlock /usr/local/bin/
  script:
    - matlock iam scan --output json --output-file report.json --quiet
    - matlock storage audit --severity HIGH --output json --output-file storage.json --quiet
  artifacts:
    paths:
      - report.json
      - storage.json
    expire_in: 30 days
```

### Fail CI on critical findings

```sh
# Exit non-zero if any CRITICAL findings exist
matlock iam scan --severity CRITICAL --output json --quiet | \
  jq -e '.findings | length == 0'
```

---

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| Table | `--output table` | Human-readable terminal output with colors |
| JSON | `--output json` | Scripts, alerting, dashboards |
| SARIF | `--output sarif` | GitHub Advanced Security, IDE integrations |

All formats can be written to a file with `--output-file path/to/file`.

---

## Version

```sh
matlock --version
# v0.1.0 (commit abc1234, built 2026-03-01T12:00:00Z)
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

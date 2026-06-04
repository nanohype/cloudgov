# cloudgov

AWS security and cost swiss army knife — single binary, zero dependencies.

Audit IAM permissions, spot cost anomalies, find orphaned resources, flag insecure storage, detect overly permissive security groups, monitor TLS certificate expiry, enforce resource tagging, check service quota utilization, save and compare scan baselines, generate HTML reports, and more — across your AWS account, plus a Kubernetes RBAC scanner.

<!-- screenshot placeholder -->
<!-- ![cloudgov iam scan output](docs/screenshots/iam-scan.png) -->

---

## Installation

### Homebrew (macOS / Linux)

```sh
brew install nanohype/tap/cloudgov
```

### go install

```sh
go install github.com/nanohype/cloudgov@latest
```

### Direct download

Pre-built binaries for Linux, macOS, and Windows are attached to every [GitHub release](https://github.com/nanohype/cloudgov/releases).

```sh
# macOS arm64 example
curl -sSL https://github.com/nanohype/cloudgov/releases/latest/download/cloudgov_Darwin_arm64.tar.gz \
  | tar -xz cloudgov
sudo mv cloudgov /usr/local/bin/
```

Verify the download against the published SHA256 checksums:

```sh
curl -sSL https://github.com/nanohype/cloudgov/releases/latest/download/checksums.txt | sha256sum --check --ignore-missing
```

### Build from source

Requires Go 1.26+ and [Task](https://taskfile.dev).

```sh
git clone https://github.com/nanohype/cloudgov.git
cd cloudgov
task build
```

---

## Credentials setup

cloudgov uses the standard AWS SDK credential chain.

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

---

## Commands

### `cloudgov iam scan` — unused and overprivileged IAM

Compares granted permissions against CloudTrail activity over the lookback window and reports unused, admin, and cross-account risks.

```sh
# Scan the current AWS account (90-day lookback)
cloudgov iam scan

# Last 30 days, show CRITICAL and HIGH only
cloudgov iam scan --days 30 --severity HIGH

# Scan a specific principal
cloudgov iam scan --principal arn:aws:iam::123456789012:role/scanner

# JSON output for downstream tooling
cloudgov iam scan --output json --output-file report.json

# SARIF output for GitHub Advanced Security
cloudgov iam scan --output sarif --output-file results.sarif

# Increase parallelism for large accounts
cloudgov iam scan --concurrency 20
```

<!-- screenshot placeholder -->
<!-- ![iam scan table output](docs/screenshots/iam-scan.png) -->

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--days` | `90` | CloudTrail lookback window in days |
| `--principal` | | Scan a single principal by name or ID |
| `--severity` | `LOW` | Minimum severity to report: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `--output` | `table` | Output format: `table`, `json`, `sarif` |
| `--output-file` | | Write output to file instead of stdout |
| `--concurrency` | `10` | Maximum parallel goroutines |
| `--profile` | | AWS named profile to use for credentials |

---

### `cloudgov iam fix` — generate Terraform remediations

Reads a JSON scan report and generates least-privilege Terraform policy files for each flagged principal.

```sh
# Generate fixes for all HIGH+ findings
cloudgov iam fix --from report.json

# Write fixes to a custom directory
cloudgov iam fix --from report.json --out ./tf-fixes

# Include MEDIUM severity fixes too
cloudgov iam fix --from report.json --severity MEDIUM
```

**Workflow**

```sh
cloudgov iam scan --output json --output-file report.json
cloudgov iam fix --from report.json --out ./fixes
ls ./fixes/
# minimal_lambda_executor.tf
# minimal_ci_deploy_role.tf
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--from` | (required) | Path to JSON report from `cloudgov iam scan --output json` |
| `--format` | `terraform` | Output format: `terraform`, `json` |
| `--out` | `./cloudgov-fixes` | Output directory for generated files |
| `--severity` | `HIGH` | Minimum severity to generate fixes for |

---

### `cloudgov cost diff` — spend delta between time windows

Compares AWS spend between the last N days and the N days before that, surfacing unexpected increases service by service.

```sh
# Compare last 30 days vs the 30 days before
cloudgov cost diff

# 7-day comparison
cloudgov cost diff --days 7

# JSON output for alerting pipelines
cloudgov cost diff --output json
```

<!-- screenshot placeholder -->
<!-- ![cost diff table output](docs/screenshots/cost-diff.png) -->

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--days` | `30` | Compare last N days vs N days before |
| `--threshold` | `0` | Only show services with >N% change (e.g. `--threshold 20`) |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

Cost increases >10% are shown in red; decreases are shown in green.

---

### `cloudgov orphans` — unused disks, IPs, and load balancers

Finds unattached disks, reserved IPs with no instance, and idle load balancers. Reports estimated monthly cost.

```sh
# Scan the current AWS account
cloudgov orphans

# Only report resources costing more than $5/month
cloudgov orphans --min-cost 5

# JSON for Slack/PagerDuty integration
cloudgov orphans --output json
```

<!-- screenshot placeholder -->
<!-- ![orphans table output](docs/screenshots/orphans.png) -->

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--min-cost` | `0` | Only report orphans with monthly cost above this USD threshold |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

The table includes a TOTAL row summing all monthly costs.

> Costs are **estimates** from on-demand list prices (e.g. ~$0.10/GB-month for gp2
> EBS), not your billed actuals — they ignore volume type, region, and discounts.
> Use them to rank waste, not to reconcile a bill; see AWS Cost Explorer for actuals.

---

### `cloudgov storage audit` — public buckets and encryption gaps

Audits object storage for public access, missing encryption, disabled versioning, and missing access logging.

```sh
# Scan the current AWS account
cloudgov storage audit

# HIGH and CRITICAL findings only
cloudgov storage audit --severity HIGH

# JSON for SIEM ingestion
cloudgov storage audit --output json --output-file storage-findings.json
```

<!-- screenshot placeholder -->
<!-- ![storage audit table output](docs/screenshots/storage-audit.png) -->

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json`, `sarif` |
| `--output-file` | | Write output to file instead of stdout |

---

### `cloudgov network audit` — overly permissive firewall rules

Checks security groups for rules that expose sensitive ports to the internet.

Severity rules:
- **CRITICAL** — `0.0.0.0/0` on SSH (22), RDP (3389), or database ports (3306, 5432, 1433, 27017, 6379, 9200)
- **HIGH** — `0.0.0.0/0` on any non-HTTP/HTTPS port
- **MEDIUM** — unrestricted egress (all traffic to `0.0.0.0/0`)

```sh
# Scan the current AWS account
cloudgov network audit

# Show CRITICAL findings only
cloudgov network audit --severity CRITICAL

# JSON output
cloudgov network audit --output json --output-file network-findings.json

# Generate shell remediation scripts alongside the table
cloudgov network audit --fix --out fixes/
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |
| `--fix` | `false` | Generate shell remediation scripts for each finding |
| `--out` | `.` | Directory to write fix scripts (used with `--fix`) |

---

### `cloudgov remediate` — generate fix scripts from a saved scan report

Read a previously-saved JSON scan report and emit shell scripts that remediate each finding. The offline equivalent of `<domain> audit --fix` — useful when you want to review findings first, gate remediation behind code review, or apply a subset by severity.

Supported report types: `storage`, `network`. Reports are read from files written via `--output json --output-file <path>` on the corresponding scan command.

```sh
# Generate fix scripts from a saved storage scan
cloudgov storage audit --output json --output-file storage.json
cloudgov remediate --type storage --from storage.json --out fixes/

# Same for network, only CRITICAL findings
cloudgov network audit --output json --output-file network.json
cloudgov remediate --type network --from network.json --severity CRITICAL --out fixes/
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--type` | (required) | Report type: `storage` or `network` |
| `--from` | (required) | Path to JSON scan report |
| `--out` | `.` | Directory to write fix scripts |
| `--severity` | `LOW` | Minimum severity to include in fix scripts |

---

### `cloudgov certs` — TLS certificate expiry

Lists TLS certificates from ACM that are expired or expiring soon.

Severity rules:
- **CRITICAL** — expired, or expiring within 7 days
- **HIGH** — expiring within 30 days
- **MEDIUM** — expiring within 60 days
- **LOW** — expiring within 90 days (default `--days` threshold)

```sh
# Warn on certs expiring within 90 days (default)
cloudgov certs

# Only show certs expiring within 30 days
cloudgov certs --days 30

# CRITICAL and HIGH only
cloudgov certs --severity HIGH

# JSON output
cloudgov certs --output json --output-file certs.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--days` | `90` | Include certs expiring within this many days |
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `cloudgov tags` — missing resource tags/labels

Audits EC2 instances, S3 buckets, RDS databases, and Lambda functions for missing required tags.

All findings are **MEDIUM** severity.

```sh
# Require owner, env, and cost-center tags
cloudgov tags --require owner,env,cost-center

# Require a smaller tag set
cloudgov tags --require owner,env

# JSON output
cloudgov tags --require owner,env --output json --output-file tags.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--require` | (required) | Comma-separated tag keys that must be present |
| `--severity` | `MEDIUM` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `cloudgov lambda audit` — Lambda resource-policy exposure (AWS)

Inspects each AWS Lambda function's resource-based policy (`lambda:GetPolicy`) for patterns that grant invoke permission too widely. This is the *resource-based* counterpart to `cloudgov iam scan` — that one checks what identities can do *from* the inside; this one checks who can invoke *into* the function from the outside.

Severity rules:
- **CRITICAL** — `Principal: "*"` or `Principal: {"AWS": "*"}` (anyone can invoke)
- **HIGH** — cross-account principal in `Principal: {"AWS": "arn:..."}` (a different account is allowed to invoke)
- **HIGH** — `Principal: {"Service": "..."}` without `aws:SourceAccount` or `aws:SourceArn` condition (confused-deputy risk)
- **HIGH** — `Action: "*"` or `Action: "lambda:*"` in any allow statement

Functions without a resource policy are silently skipped — they're only reachable via identity-based IAM, which the IAM scan already covers.

```sh
# Audit all Lambda resource policies in the current AWS account
cloudgov lambda audit

# CRITICAL only, JSON output
cloudgov lambda audit --severity CRITICAL --output json --output-file lambda.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `cloudgov k8s rbac` — over-privileged Kubernetes RBAC

Scans cluster-scoped ClusterRoles and ClusterRoleBindings for the patterns that produce real incidents: wildcard verbs/resources, dangerous verbs (create/update/patch/delete) on wildcard resources, and bindings to broad subject groups (`system:authenticated`, `system:unauthenticated`, `system:masters`). Built-in default roles (`cluster-admin`, `admin`, `edit`, `view`, `system:*`, `kubeadm:*`) are skipped so the output focuses on user-introduced risk.

Connection uses the standard kubeconfig chain: `--kubeconfig` flag → `$KUBECONFIG` → `~/.kube/config` → in-cluster service-account token.

```sh
# Scan the cluster of the current kubeconfig context
cloudgov k8s rbac

# Use a specific kubeconfig
cloudgov k8s rbac --kubeconfig /path/to/kubeconfig

# JSON output for CI
cloudgov k8s rbac --output json --output-file rbac.json

# HIGH and above only
cloudgov k8s rbac --severity HIGH
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--kubeconfig` | (chain) | Path to kubeconfig file |
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `cloudgov secrets scan` — leaked credentials in cloud resources

Scans Lambda environment variables, ECS task definitions, EC2 user data, and similar runtime configuration for embedded secrets — AWS keys, Slack tokens, private keys, GitHub tokens, generic high-entropy strings, and third-party cloud credentials (GCP service-account keys, Azure connection strings) leaked into AWS resources.

```sh
# Scan the current AWS account
cloudgov secrets scan

# HIGH and above
cloudgov secrets scan --severity HIGH

# SARIF output for GitHub Advanced Security
cloudgov secrets scan --output sarif --output-file secrets.sarif
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json`, `sarif` |
| `--output-file` | | Write output to file instead of stdout |

---

### `cloudgov compliance <benchmark>` — map findings to compliance controls

Loads JSON scan reports from prior cloudgov runs and maps the findings to controls in a named benchmark, producing a pass/fail evaluation per control.

Available benchmarks: `cis-aws-v3`, `soc2`.

```sh
# Produce JSON reports first
cloudgov iam scan --output json --output-file iam.json
cloudgov storage audit --output json --output-file storage.json

# Then evaluate against a benchmark
cloudgov compliance cis-aws-v3 --iam-report iam.json --storage-report storage.json

# JSON output for ingest into a dashboard
cloudgov compliance soc2 --iam-report iam.json --output json --output-file soc2.json
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

### `cloudgov drift <tfstate>` — Terraform state vs live cloud

Reads a `terraform.tfstate` file and checks each managed resource against the AWS API to detect modifications or deletions outside Terraform. Supports security groups, IAM policies, and S3 buckets.

```sh
# Local state file
cloudgov drift terraform.tfstate

# Filter to a single resource type
cloudgov drift terraform.tfstate --resource-type aws_security_group

# Lower concurrency
cloudgov drift terraform.tfstate --concurrency 5

# JSON output
cloudgov drift terraform.tfstate --output json --output-file drift.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--resource-type` | | Filter to a single Terraform resource type |
| `--concurrency` | `10` | Max concurrent API calls |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `cloudgov audit` — unified full-spectrum audit

Runs all security and cost scans (IAM, storage, network, orphans, certs, tags, secrets) in one shot and produces a single combined report. Skip specific domains with `--skip`.

```sh
# Full audit of the current AWS account
cloudgov audit

# Skip IAM and certs domains
cloudgov audit --skip iam,certs

# HIGH and CRITICAL findings only, JSON output
cloudgov audit --severity HIGH --output json --output-file audit.json

# SARIF output for GitHub Advanced Security
cloudgov audit --output sarif --output-file audit.sarif

# Custom thresholds
cloudgov audit --iam-days 30 --cert-days 60 --require-tags owner,env
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
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

`cloudgov audit --sink <spec>` posts a digest of the run to an external system after the scan completes. Sinks fire on a best-effort basis — one bad sink does not block the others, and audit exit code is unaffected. The flag is repeatable, so you can deliver to several destinations at once.

| Spec form | What it does |
|---|---|
| `slack:<webhook-url>` | Block Kit message with severity-coded header, per-domain summary, top 10 findings, and optional report link |
| `webhook:<url>` | POSTs the raw JSON digest to any URL; receivers parse it however they like |
| `pagerduty:<routing-key>` | PagerDuty Events API v2 trigger — only fires when the digest contains at least one critical or high finding (avoids alert fatigue) |

```sh
# Post a Slack notification on every audit run
cloudgov audit --sink slack:https://hooks.slack.com/services/T00/B00/XXX

# Page on-call AND notify Slack AND forward to a custom collector
cloudgov audit \
  --sink slack:https://hooks.slack.com/services/T00/B00/XXX \
  --sink pagerduty:my-pd-routing-key \
  --sink webhook:https://collector.example.com/cloudgov \
  --report-url https://reports.example.com/audit-$(date +%F).html
```

---

### `cloudgov inventory` — list all cloud resources

Lists all AWS resources with type, region, tags, and creation date. Groups by type and region for a complete asset overview.

```sh
# List all resources in the current AWS account
cloudgov inventory

# Filter to specific resource types
cloudgov inventory --type ec2,s3,lambda

# JSON output
cloudgov inventory --output json --output-file inventory.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--type` | all | Resource types to list (e.g. `ec2`, `s3`, `lambda`) |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `cloudgov quota` — service quota utilization

Checks AWS service quota usage to prevent outages from silently hitting limits. Reports IAM, EC2, S3, Lambda, and RDS quotas.

```sh
# All quotas
cloudgov quota

# Only quotas above 50% utilization
cloudgov quota --threshold 50

# JSON output
cloudgov quota --output json --output-file quotas.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--threshold` | `0` | Minimum utilization percentage to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

Utilization is color-coded: green (<50%), yellow (50-80%), red (>80%).

---

### `cloudgov baseline` — save and manage scan baselines

Save any scan report as a named baseline for later comparison with `cloudgov compare`.

```sh
# Save a baseline from a scan report
cloudgov iam scan --output json --output-file scan.json
cloudgov baseline save --from scan.json --name pre-deploy

# List saved baselines
cloudgov baseline list

# Delete a baseline
cloudgov baseline delete --name old-scan
```

Baselines are stored in `~/.cloudgov/baselines/`.

**Subcommands**

| Subcommand | Description |
|------------|-------------|
| `baseline save --from <file> --name <name>` | Save a report as a named baseline |
| `baseline list` | List all saved baselines with dates |
| `baseline delete --name <name>` | Delete a saved baseline |

---

### `cloudgov compare` — diff two scan reports

Compares two scan reports (or a saved baseline against a current report) and classifies each finding as new, resolved, or unchanged.

```sh
# Compare a saved baseline against a new scan
cloudgov compare --baseline pre-deploy --current scan-after.json

# Compare two report files directly
cloudgov compare --from old-report.json --to new-report.json

# JSON output
cloudgov compare --from old.json --to new.json --output json
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
cloudgov audit --output json --output-file audit.json
cloudgov baseline save --from audit.json --name pre-deploy-v2

# After the deploy: scan again and compare
cloudgov audit --output json --output-file audit-after.json
cloudgov compare --baseline pre-deploy-v2 --current audit-after.json

# Output shows:
#   +NEW        findings introduced since the baseline
#   -RESOLVED   findings that no longer appear
#   =UNCHANGED  findings present in both
```

You can also skip baselines and compare any two JSON files directly:

```sh
cloudgov compare --from monday-scan.json --to friday-scan.json --output json
```

---

### `cloudgov report` — generate HTML executive summary

Generates a standalone, self-contained HTML report from any JSON scan output. Includes summary cards, severity breakdown, domain-specific tables, and client-side table sorting. Supports light and dark mode via `prefers-color-scheme`.

```sh
# Generate from an audit report
cloudgov audit --output json --output-file audit.json
cloudgov report --from audit.json --out report.html --open

# Generate from any scan report
cloudgov report --from iam-scan.json --out iam-report.html

# Explicit type override
cloudgov report --from data.json --type orphans --out orphans.html
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
name: cloudgov security scan

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

      - name: Install cloudgov
        run: |
          curl -sSL https://github.com/nanohype/cloudgov/releases/latest/download/cloudgov_Linux_amd64.tar.gz \
            | tar -xz cloudgov
          sudo mv cloudgov /usr/local/bin/

      - name: Run IAM scan
        env:
          AWS_ROLE_ARN: ${{ secrets.CLOUDGOV_ROLE_ARN }}
          AWS_REGION: us-east-1
        run: |
          cloudgov iam scan \
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
name: cloudgov full audit

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

      - name: Install cloudgov
        run: |
          curl -sSL https://github.com/nanohype/cloudgov/releases/latest/download/cloudgov_Linux_amd64.tar.gz \
            | tar -xz cloudgov
          sudo mv cloudgov /usr/local/bin/

      - name: Run full audit
        env:
          AWS_ROLE_ARN: ${{ secrets.CLOUDGOV_ROLE_ARN }}
          AWS_REGION: us-east-1
        run: |
          cloudgov audit \
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
cloudgov:
  image: ubuntu:24.04
  before_script:
    - curl -sSL https://github.com/nanohype/cloudgov/releases/latest/download/cloudgov_Linux_amd64.tar.gz
        | tar -xz cloudgov
    - mv cloudgov /usr/local/bin/
  script:
    - cloudgov iam scan --output json --output-file report.json --quiet
    - cloudgov storage audit --severity HIGH --output json --output-file storage.json --quiet
  artifacts:
    paths:
      - report.json
      - storage.json
    expire_in: 30 days
```

### Fail CI on critical findings

```sh
# Exit non-zero if any CRITICAL findings exist
cloudgov iam scan --severity CRITICAL --output json --quiet | \
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
cloudgov --version
# v0.1.0 (commit abc1234, built 2026-03-01T12:00:00Z)
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

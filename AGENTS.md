# cloudgov — agent entry point

AWS security & cost governance CLI. Single static binary, AWS-only, plus a
Kubernetes RBAC scanner and a nanohype Platform-tenant conformance auditor. Five
domains: IAM least-privilege, cost, infrastructure
hygiene (orphans, storage, network, certs, tags), security posture (secrets,
compliance, drift, full audit), and operational visibility (inventory, quotas).

## Invoke via MCP (preferred)

cloudgov runs as a Model Context Protocol server over stdio. Register it once:

```sh
claude mcp add --transport stdio cloudgov -- cloudgov mcp
```

Every tool returns the same JSON report the CLI emits with `--output json`. All
params are optional unless marked **required**.

| tool | what it does | key params |
|------|--------------|------------|
| `audit` | full security + cost audit in one call | `severity`, `skip[]`, `iam_days`, `cert_days`, `required_tags[]` |
| `iam_scan` | unused / admin / wildcard / cross-account IAM | `profile`, `days`, `severity` |
| `storage_audit` | public / unencrypted / unversioned / unlogged S3 | `severity` |
| `network_audit` | overly permissive security groups | `severity` |
| `secrets_scan` | embedded secrets, incl. leaked third-party cloud creds | `severity` |
| `certs` | TLS certs (ACM) expiring soon | `severity`, `days` |
| `tags` | resources missing required tags | **`required[]`**, `severity` |
| `orphans` | unused disks / IPs / LBs + monthly cost | `min_monthly_cost` |
| `quota` | service quota utilization vs limits | `min_utilization` |
| `inventory` | list AWS resources | `types[]` |
| `cost_diff` | spend delta between two windows | `days`, `threshold`, `severity` |
| `drift` | Terraform state vs live AWS | **`tfstate_path`**, `resource_type` |
| `compliance` | map saved reports to a benchmark | **`benchmark`** (`cis-aws-v3`/`soc2`), `*_report` paths |
| `k8s_rbac` | over-privileged cluster RBAC | `kubeconfig`, `severity` |
| `lambda_audit` | Lambda resource-policy exposure | `severity` |
| `platform_audit` | nanohype Platform-tenant conformance vs the eks-agent-platform contract | `kubeconfig`, `severity` |

Credentials resolve via the standard AWS SDK chain and kubeconfig chain — the
same as the CLI. The server is read-only; it never mutates cloud or cluster state.

## Invoke via CLI (scripts / CI)

Every command produces machine-readable output and can gate on severity:

```sh
cloudgov <command> --output json --quiet     # stable JSON to stdout
cloudgov <command> --output sarif            # SARIF 2.1.0 (security domains)
cloudgov <command> --fail-on HIGH            # exit 2 if any finding >= HIGH
```

**Exit codes:** `0` = clean, `1` = command error, `2` = a finding met or exceeded
`--fail-on`, `3` = the scan could not observe everything it was asked to, so the
result is not evidence either way. (`--fail-on` is unset by default, so exit
stays 0/1 without it.)

Exit `3` matters because `0` is read as evidence *for* approval. A denied
`GetBucketVersioning` looks exactly like a versioned bucket if the error is
dropped, so a scan run with partial permissions must be distinguishable from a
scan that found nothing. What could not be read is listed on stderr and in the
JSON report's `incomplete` array.

JSON report schemas are Go structs in `internal/output/<domain>.go` — one typed
envelope per domain (`iamReport`, `storageReport`, …), sharing the writer in
`internal/output/jsoncore.go`. SARIF is emitted by iam,
storage, network, certs, secrets, audit, k8s, lambda, compliance, and drift.

## Use in the fab merge-gate

A `qa-security` / `compliance-curator` role can build evidence-bound verdicts
straight from cloudgov:

- **TRANSCRIPTS** — run `cloudgov audit --output json --fail-on HIGH --quiet`;
  record the command, its exit code, and stdout.
- **CITATIONS** — cite each finding's `provider` / `type` / `resource` / `detail`
  from the JSON.
- Exit `2` is a hard signal toward REJECT / REQUEST_CHANGES; exit `0` supports
  APPROVE. Exit `3` supports neither — the run did not see enough of the account
  to be evidence. Treat it as a blocked gate and fix the credentials, or cite the
  `incomplete` array to scope what the verdict does not cover.

## Boundaries

cloudgov audits **deployed/runtime** AWS + cluster posture. It does not *enforce*
(the eks-agent-platform operator reconciles and enforces the Platform contract),
and it does not grade **build-time** standards — version currency, the source side
of the LLM policy, the quality rubric, and Helm/chart artifact structure stay with
fab's quality-check skill and merge-gate curators.

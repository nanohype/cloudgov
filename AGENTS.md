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
| `repo_audit` | GitHub branch protection, required checks and Dependabot state vs the committed expected shape | `org`, `expected`, `severity` |
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

The `kubeconfig` parameter is narrower over MCP than the `--kubeconfig` flag is
over the CLI: a file named through the parameter may not authenticate by running
an exec credential plugin, and the call fails naming the command it refused. The
plugin's command line comes from the file, so naming the file chooses which
binary runs inside a process holding live cloud credentials — authority an
operator typing a path already holds and a tool argument does not. Omit the
parameter to use the server's own kubeconfig chain, where an exec plugin is the
operator's own choice and is honoured.

## Invoke via CLI (scripts / CI)

Every command produces machine-readable output and can gate on severity:

```sh
cloudgov <command> --output json --quiet     # stable JSON to stdout
cloudgov <command> --output sarif            # SARIF 2.1.0 (security domains)
cloudgov <command> --fail-on HIGH            # exit 2 if any finding >= HIGH
cloudgov <command> --regions us-west-2       # narrow the region sweep
```

Regional scans cover every region enabled for the account unless `--regions`
narrows them, so a finding's `region` field is the region it was read from
rather than the one the caller's profile named. Global services (IAM, Cost
Explorer, the S3 bucket list) are scanned once and report `global`. A region
that cannot be read is recorded as incomplete, which is exit `3` — the scope was
narrower than asked for, so a clean result is not evidence.

**Exit codes:** `0` = clean, `1` = command error, `2` = a finding met or exceeded
`--fail-on`, `3` = the scan could not observe everything it was asked to, so the
result is not evidence either way. (`--fail-on` is unset by default, so exit
stays 0/1 without it.)

Exit `3` matters because `0` is read as evidence *for* approval. A denied
`GetBucketVersioning` looks exactly like a versioned bucket if the error is
dropped, so a scan run with partial permissions must be distinguishable from a
scan that found nothing. What could not be read is listed on stderr and in the
JSON report's `incomplete` array.

**Scope of the contract, stated exactly.** Every command that reads a cloud
account honours it — all 14: `audit`, `iam scan`, `storage audit`,
`network audit`, `certs`, `tags`, `secrets scan`, `orphans`, `quota`,
`inventory`, `cost diff`, `drift`, `lambda audit`, `platform audit`. `repo audit`
honours it too, over the GitHub API rather than a cloud account.

Two commands reach the contract by a route other than a provider's recorded
warnings, because the fact they must report does not arrive there.

`drift` compares a tfstate against live AWS. A resource whose live state cannot
be read is recorded as a `DriftError` row, and `drift.Incomplete` lifts every
such row into the run's incomplete list. Without that lift the row is a table
cell: the exit code and the `incomplete` array would report a tfstate as
matching an account the scan never saw.

`platform audit` reads both a cluster and an AWS account. It returns its own
list of conformance checks it could not perform, alongside the findings, and the
command appends it to the AWS provider's warnings. The list is separate from the
findings because findings are severity-filtered and the severity that fits "I
could not look" sits below the floor every caller sets — so carrying the record
as a finding would delete it exactly when it matters. Absent AWS credentials are
recorded the same way: skipping a whole class of conformance checks is not the
same as passing them.

The conformance test (`cmd/incomplete_contract_test.go`) enumerates every
`cmd/` file that imports a provider package and fails the build on any that is
neither gated nor explicitly exempt. Enumerating by import rather than by
construction idiom is what makes the population the set of commands that exist
rather than the set the check knows how to recognise: a command that builds a
provider by an idiom nobody has written yet is still counted, and must still be
gated or exempted by name.

It does not apply to commands that read no account at all: `compare`, `report`,
`baseline`, `remediate` and `compliance` work from files already on disk.

`repo audit` reads the GitHub API rather than a cloud account and honours the
contract anyway. A repository `gh` cannot read produces no finding, and the tool
used to file that as `NO_BRANCH_PROTECTION` at HIGH — but `gh` returns the same
error for an unreachable API, an unauthenticated CLI, a rate limit and a token
genuinely missing the scope, so naming one of those was a guess in the shape of a
diagnosis. Worse, a gate reading that finding sees a governance breach where
there is an unread repository. Unreadable repositories are recorded as incomplete
observations carrying what `gh` actually said.

`k8s rbac` is exempt for a different reason — the Kubernetes
provider returns errors rather than partial observations and implements no
`IncompleteReporter`, so gating it would assert a guarantee the layer beneath
cannot supply. Those exit 0/1/2 only.

Exit `3` requires `--fail-on`. Passing it is what declares the run a gate;
without it the run is informational and the incompletions are reported on stderr
and in the JSON without changing the exit code.

Over MCP there is no exit code, so the `incomplete` array in the response is the
only carrier. Every tool that reads a cloud account populates it.

The key is always present, and a run that observed everything reports it as `[]`.
An omitted key and a `null` are the same ambiguity — neither can be told apart
from a tool that does not describe its own coverage — so an empty array is how a
tool says "I looked at all of it", positively rather than by silence. Tools that
do not populate the array in their own handler are exempt by name, each with the
reason on file: `k8s_rbac` and `compliance` read no cloud account, and `audit`
carries the record on its report struct instead. `cmd/mcp_incomplete_test.go`
pairs every registered tool with its own handler to enforce that — an exemption
naming a tool that does not exist fails the build, as does a tool that reads an
account and never reaches the record, and as does an exempt tool that computes
the array anyway.

The `severity` parameter is validated rather than coerced. An unrecognised value
is refused, because severity ranking treats an unknown level as below every real
one — so a filter argument with a typo would silently widen the request instead
of narrowing it, and return every finding at every level.

JSON report schemas are Go structs in `internal/output/<domain>.go` — one typed
envelope per domain (`iamReport`, `storageReport`, …), sharing the writer in
`internal/output/jsoncore.go`. SARIF is emitted by iam, storage, certs, secrets, audit, k8s, lambda,
platform, compliance, and drift. `network`, `tags`, `orphans`, `quota`,
`inventory`, `cost diff` and `repo audit` emit `table` and `json` only.

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

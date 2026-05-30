package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/nanohype/cloudgov/internal/audit"
	"github.com/nanohype/cloudgov/internal/certs"
	"github.com/nanohype/cloudgov/internal/cloud"
	cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"
	cloudk8s "github.com/nanohype/cloudgov/internal/cloud/k8s"
	"github.com/nanohype/cloudgov/internal/compliance"
	"github.com/nanohype/cloudgov/internal/cost"
	"github.com/nanohype/cloudgov/internal/drift"
	"github.com/nanohype/cloudgov/internal/iam"
	"github.com/nanohype/cloudgov/internal/inventory"
	"github.com/nanohype/cloudgov/internal/network"
	"github.com/nanohype/cloudgov/internal/orphans"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/platform"
	"github.com/nanohype/cloudgov/internal/quota"
	"github.com/nanohype/cloudgov/internal/secrets"
	"github.com/nanohype/cloudgov/internal/storage"
	"github.com/nanohype/cloudgov/internal/tags"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run cloudgov as an MCP server (stdio) for AI agents",
	Long: `Expose cloudgov's scans and audits as Model Context Protocol tools over
stdio, so AI agents (e.g. the fab factory) can invoke them natively.

Each tool returns the same JSON report the CLI emits with --output json.
Register it with an MCP client, e.g.:

  claude mcp add --transport stdio cloudgov -- cloudgov mcp

AWS credentials and kubeconfig are resolved exactly as for the CLI
commands (standard SDK chains).`,
	RunE: runMCP,
}

func runMCP(_ *cobra.Command, _ []string) error {
	s := mcp.NewServer(&mcp.Implementation{Name: "cloudgov", Version: Version}, nil)
	registerMCPTools(s)
	// Run blocks until the client disconnects, which surfaces as io.EOF on the
	// stdio transport — a clean shutdown, not an error.
	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// --- tool input schemas (descriptions surface to the agent via jsonschema tags) ---

type severityInput struct {
	Severity string `json:"severity,omitempty" jsonschema:"minimum severity to report: CRITICAL, HIGH, MEDIUM, or LOW (default LOW)"`
}

type iamInput struct {
	Profile  string `json:"profile,omitempty" jsonschema:"AWS named profile to use"`
	Days     int    `json:"days,omitempty" jsonschema:"audit-log lookback window in days (default 90)"`
	Severity string `json:"severity,omitempty" jsonschema:"minimum severity to report (default LOW)"`
}

type certsInput struct {
	Severity string `json:"severity,omitempty"`
	Days     int    `json:"days,omitempty" jsonschema:"include certificates expiring within this many days (default 90)"`
}

type tagsInput struct {
	Severity string   `json:"severity,omitempty"`
	Required []string `json:"required" jsonschema:"tag/label keys that must be present on every resource"`
}

type orphansInput struct {
	MinMonthlyCost float64 `json:"min_monthly_cost,omitempty" jsonschema:"only report orphans above this monthly USD cost"`
}

type quotaInput struct {
	MinUtilization float64 `json:"min_utilization,omitempty" jsonschema:"only report quotas above this utilization percentage"`
}

type inventoryInput struct {
	Types []string `json:"types,omitempty" jsonschema:"resource types to include (e.g. ec2, s3, lambda); empty = all"`
}

type costInput struct {
	Days      int     `json:"days,omitempty" jsonschema:"compare the last N days against the prior N days (default 30)"`
	Threshold float64 `json:"threshold,omitempty" jsonschema:"only include services whose spend changed by more than this percent"`
	Severity  string  `json:"severity,omitempty"`
}

type driftInput struct {
	TFStatePath  string `json:"tfstate_path" jsonschema:"path to a terraform.tfstate file to compare against live AWS state"`
	ResourceType string `json:"resource_type,omitempty" jsonschema:"filter to a single Terraform resource type"`
}

type auditInput struct {
	Severity     string   `json:"severity,omitempty"`
	Skip         []string `json:"skip,omitempty" jsonschema:"domains to skip: iam, storage, network, orphans, certs, tags, secrets"`
	IAMDays      int      `json:"iam_days,omitempty" jsonschema:"IAM audit-log lookback in days (default 90)"`
	CertDays     int      `json:"cert_days,omitempty" jsonschema:"certificate expiry threshold in days (default 90)"`
	RequiredTags []string `json:"required_tags,omitempty" jsonschema:"required tag keys for the tag-audit domain"`
}

type k8sInput struct {
	Kubeconfig string `json:"kubeconfig,omitempty" jsonschema:"path to kubeconfig (default: standard chain)"`
	Severity   string `json:"severity,omitempty"`
}

type complianceInput struct {
	Benchmark     string `json:"benchmark" jsonschema:"benchmark id: cis-aws-v3 or soc2"`
	IAMReport     string `json:"iam_report,omitempty" jsonschema:"path to an iam scan JSON report"`
	StorageReport string `json:"storage_report,omitempty"`
	NetworkReport string `json:"network_report,omitempty"`
	CertsReport   string `json:"certs_report,omitempty"`
	TagsReport    string `json:"tags_report,omitempty"`
}

// registerMCPTools wires every scan/audit operation as an MCP tool. Each handler
// reuses the same resolve*Providers helpers and internal scanners as the CLI and
// returns the identical JSON report.
func registerMCPTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{Name: "iam_scan", Description: "Scan AWS IAM principals for unused, admin, wildcard-resource, and cross-account risk."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in iamInput) (*mcp.CallToolResult, any, error) {
			providers, err := resolveIAMProviders(ctx, in.Profile)
			if err != nil {
				return nil, nil, err
			}
			res, err := iam.Scan(ctx, providers[0], iam.ScanOptions{
				Days:        orDefault(in.Days, 90),
				MinSeverity: mcpSeverity(in.Severity),
				Concurrency: 10,
			})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(func(w io.Writer) error {
				return output.WriteIAM(w, res.Findings, res.Principals, res.UsedPermissions)
			})
		})

	mcp.AddTool(s, &mcp.Tool{Name: "storage_audit", Description: "Audit S3 buckets for public access, missing encryption, versioning, and logging."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in severityInput) (*mcp.CallToolResult, any, error) {
			providers, err := resolveStorageProviders(ctx)
			if err != nil {
				return nil, nil, err
			}
			findings, err := storage.Scan(ctx, providers, storage.ScanOptions{MinSeverity: mcpSeverity(in.Severity)})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(func(w io.Writer) error { return output.WriteStorage(w, findings) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "network_audit", Description: "Audit security groups for overly permissive ingress/egress rules."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in severityInput) (*mcp.CallToolResult, any, error) {
			providers, err := resolveNetworkProviders(ctx)
			if err != nil {
				return nil, nil, err
			}
			findings, err := network.Scan(ctx, providers, network.ScanOptions{MinSeverity: mcpSeverity(in.Severity)})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(func(w io.Writer) error { return output.WriteNetwork(w, findings) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "certs", Description: "List TLS certificates (ACM) expiring within a threshold."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in certsInput) (*mcp.CallToolResult, any, error) {
			providers, err := resolveCertProviders(ctx)
			if err != nil {
				return nil, nil, err
			}
			findings, err := certs.Scan(ctx, providers, certs.ScanOptions{MinSeverity: mcpSeverity(in.Severity), Days: orDefault(in.Days, 90)})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(func(w io.Writer) error { return output.WriteCerts(w, findings) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "tags", Description: "Find AWS resources missing required tags."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in tagsInput) (*mcp.CallToolResult, any, error) {
			providers, err := resolveTagProviders(ctx)
			if err != nil {
				return nil, nil, err
			}
			findings, err := tags.Scan(ctx, providers, tags.ScanOptions{MinSeverity: mcpSeverity(in.Severity), Required: in.Required})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(func(w io.Writer) error { return output.WriteTags(w, findings) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "secrets_scan", Description: "Scan AWS runtime config (Lambda env, ECS task defs, EC2 user data) for embedded secrets, including leaked third-party cloud credentials."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in severityInput) (*mcp.CallToolResult, any, error) {
			providers, err := resolveSecretsProviders(ctx)
			if err != nil {
				return nil, nil, err
			}
			findings, err := secrets.ScanProviders(ctx, providers, secrets.ScanOptions{MinSeverity: mcpSeverity(in.Severity)})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(func(w io.Writer) error { return output.WriteSecrets(w, findings) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "orphans", Description: "Find unused AWS resources (unattached disks, idle IPs, idle load balancers) wasting money."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in orphansInput) (*mcp.CallToolResult, any, error) {
			providers, err := resolveOrphansProviders(ctx)
			if err != nil {
				return nil, nil, err
			}
			res, err := orphans.Scan(ctx, providers, orphans.ScanOptions{MinMonthlyCost: in.MinMonthlyCost})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(func(w io.Writer) error { return output.WriteOrphans(w, res) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "quota", Description: "Report AWS service quota utilization vs limits."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in quotaInput) (*mcp.CallToolResult, any, error) {
			providers, err := resolveQuotaProviders(ctx)
			if err != nil {
				return nil, nil, err
			}
			res, err := quota.Scan(ctx, providers, quota.ScanOptions{MinUtilization: in.MinUtilization})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(func(w io.Writer) error { return output.WriteQuotas(w, res) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "inventory", Description: "List AWS resources across types with region, tags, and creation date."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in inventoryInput) (*mcp.CallToolResult, any, error) {
			providers, err := resolveInventoryProviders(ctx)
			if err != nil {
				return nil, nil, err
			}
			res, err := inventory.Scan(ctx, providers, inventory.ScanOptions{TypeFilter: in.Types})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(func(w io.Writer) error { return output.WriteInventory(w, res) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "cost_diff", Description: "Compare AWS spend between two time windows and surface per-service deltas."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in costInput) (*mcp.CallToolResult, any, error) {
			providers, err := resolveCostProviders(ctx)
			if err != nil {
				return nil, nil, err
			}
			diffs, err := cost.Scan(ctx, providers, cost.ScanOptions{Days: orDefault(in.Days, 30), Threshold: in.Threshold, MinSeverity: mcpSeverity(in.Severity)})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(func(w io.Writer) error { return output.WriteCost(w, diffs) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "drift", Description: "Compare a Terraform state file against live AWS resources to detect drift."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in driftInput) (*mcp.CallToolResult, any, error) {
			resources, err := drift.ParseTFState(in.TFStatePath)
			if err != nil {
				return nil, nil, err
			}
			providers, err := resolveDriftProviders(ctx)
			if err != nil {
				return nil, nil, err
			}
			results, err := drift.Scan(ctx, resources, providers, drift.ScanOptions{ResourceType: in.ResourceType, Concurrency: 10})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(func(w io.Writer) error { return output.WriteDrift(w, results) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "audit", Description: "Run the full security + cost audit (IAM, storage, network, orphans, certs, tags, secrets) in one shot."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in auditInput) (*mcp.CallToolResult, any, error) {
			providers, err := buildAuditProviders(ctx)
			if err != nil {
				return nil, nil, err
			}
			skip := make(map[string]bool, len(in.Skip))
			for _, d := range in.Skip {
				skip[strings.ToLower(d)] = true
			}
			report, err := audit.Run(ctx, providers, audit.Options{
				Skip:         skip,
				MinSeverity:  mcpSeverity(in.Severity),
				IAMDays:      orDefault(in.IAMDays, 90),
				CertDays:     orDefault(in.CertDays, 90),
				RequiredTags: in.RequiredTags,
				Concurrency:  10,
				Quiet:        true,
			})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(func(w io.Writer) error { return output.WriteAudit(w, report) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "k8s_rbac", Description: "Scan cluster-scoped Kubernetes RBAC for over-privileged ClusterRoles and broad bindings."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in k8sInput) (*mcp.CallToolResult, any, error) {
			p, err := cloudk8s.New(ctx, in.Kubeconfig)
			if err != nil {
				return nil, nil, err
			}
			findings, err := p.ScanRBAC(ctx)
			if err != nil {
				return nil, nil, err
			}
			findings = filterK8sBySeverity(findings, strings.ToUpper(orString(in.Severity, "LOW")))
			return jsonResult(func(w io.Writer) error { return output.WriteK8sFindings(w, findings) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "lambda_audit", Description: "Audit AWS Lambda resource-based policies for public-invoke and confused-deputy risk."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in severityInput) (*mcp.CallToolResult, any, error) {
			p, err := cloudaws.New(ctx)
			if err != nil {
				return nil, nil, err
			}
			findings, err := p.AuditLambdaPolicies(ctx)
			if err != nil {
				return nil, nil, err
			}
			findings = filterLambdaBySeverity(findings, mcpSeverity(in.Severity))
			return jsonResult(func(w io.Writer) error { return output.WriteLambdaPolicy(w, findings) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "compliance", Description: "Map prior scan JSON reports to a compliance benchmark (cis-aws-v3 or soc2)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in complianceInput) (*mcp.CallToolResult, any, error) {
			benchmark := compliance.GetBenchmark(strings.ToLower(in.Benchmark))
			if benchmark == nil {
				return nil, nil, fmt.Errorf("unknown benchmark %q; available: %s", in.Benchmark, strings.Join(compliance.AvailableBenchmarks(), ", "))
			}
			var input compliance.InputFindings
			if err := loadComplianceReports(in, &input); err != nil {
				return nil, nil, err
			}
			report := compliance.Evaluate(benchmark, input)
			return jsonResult(func(w io.Writer) error { return output.WriteCompliance(w, report) })
		})

	mcp.AddTool(s, &mcp.Tool{Name: "platform_audit", Description: "Audit nanohype Platform tenants for conformance to the eks-agent-platform contract: namespace + PSS, ResourceQuota, tenant-egress NetworkPolicy, and tenant-runtime IRSA wiring."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in k8sInput) (*mcp.CallToolResult, any, error) {
			clients, err := cloudk8s.NewClients(ctx, in.Kubeconfig)
			if err != nil {
				return nil, nil, err
			}
			var roles platform.RoleReader
			if awsP, aerr := cloudaws.New(ctx); aerr == nil && awsP.Detect(ctx) {
				roles = awsP
			}
			findings, err := platform.Audit(ctx, clients.Typed, clients.Dynamic, roles)
			if err != nil {
				return nil, nil, err
			}
			findings = filterPlatformBySeverity(findings, strings.ToUpper(orString(in.Severity, "LOW")))
			return jsonResult(func(w io.Writer) error { return output.WritePlatform(w, findings) })
		})
}

func loadComplianceReports(in complianceInput, input *compliance.InputFindings) error {
	if in.IAMReport != "" {
		f, err := compliance.LoadIAMReport(in.IAMReport)
		if err != nil {
			return err
		}
		input.IAM = f
	}
	if in.StorageReport != "" {
		f, err := compliance.LoadStorageReport(in.StorageReport)
		if err != nil {
			return err
		}
		input.Storage = f
	}
	if in.NetworkReport != "" {
		f, err := compliance.LoadNetworkReport(in.NetworkReport)
		if err != nil {
			return err
		}
		input.Network = f
	}
	if in.CertsReport != "" {
		f, err := compliance.LoadCertsReport(in.CertsReport)
		if err != nil {
			return err
		}
		input.Certs = f
	}
	if in.TagsReport != "" {
		f, err := compliance.LoadTagsReport(in.TagsReport)
		if err != nil {
			return err
		}
		input.Tags = f
	}
	return nil
}

// jsonResult renders a report via one of the output.Write* funcs into a single
// MCP text-content result (the same JSON the CLI emits).
func jsonResult(write func(io.Writer) error) (*mcp.CallToolResult, any, error) {
	var buf bytes.Buffer
	if err := write(&buf); err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: buf.String()}}}, nil, nil
}

func mcpSeverity(s string) cloud.Severity {
	if s == "" {
		return cloud.SeverityLow
	}
	return cloud.Severity(strings.ToUpper(s))
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func orString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

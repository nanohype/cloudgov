package aws

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	smithymiddleware "github.com/aws/smithy-go/middleware"
)

// Provider implements all CloudGov provider interfaces for AWS.
//
// Per-domain SDK clients are interface-typed and constructed at New(). Tests
// build Provider directly with hand-written mocks satisfying the same
// interfaces, bypassing New() entirely. See iam.go for the canonical pattern.
//
// Each SDK service gets one field; the corresponding xxxAPI interface lives in
// the file that first uses it (e.g. iamAPI in iam.go, ec2API in orphans.go).
// When a second file needs methods from the same SDK, extend the existing
// interface rather than declaring a parallel one.
type Provider struct {
	cfg          awssdk.Config
	iam          iamAPI
	cloudtrail   cloudtrailAPI
	ec2          ec2API
	elbv2        elbv2API
	costexplorer costExplorerAPI
	s3           s3API
	// s3ForRegion returns an s3API bound to a specific region. Storage scans
	// must reach buckets outside the configured default region, so this factory
	// is overridable by tests (which typically return the same mock regardless
	// of region).
	s3ForRegion    func(region string) s3API
	acm            acmAPI
	rds            rdsAPI
	lambda         lambdaAPI
	ecs            ecsAPI
	ssm            ssmAPI
	cloudformation cloudFormationAPI
	servicequotas  serviceQuotasAPI
	eks            eksAPI
	logs           logsAPI
	sqs            sqsAPI
	eventbridge    eventBridgeAPI
	dynamodb       dynamodbAPI
	sns            snsAPI

	// warnw receives non-fatal pagination/skip warnings. nil means os.Stderr;
	// WithQuiet sets it to io.Discard so --quiet silences provider-level noise.
	warnw io.Writer

	// parent links a region-bound provider from forRegion back to the provider
	// that built it. Warnings and the resolved region set live on the root, so a
	// finding missed in one region surfaces in the run's Incomplete output
	// instead of being stranded on a sub-provider nobody asks. nil on the root.
	parent *Provider

	// regions is the explicit --regions list. Empty means every region enabled
	// for the account, discovered once via DescribeRegions.
	regions         []string
	regionsOnce     sync.Once
	resolvedRegions []string

	// clientsForRegion builds a provider whose regional clients are bound to a
	// given region. nil (the zero value tests get) makes forRegion a no-op, so a
	// mock-backed provider scans once with the mocks it was given. See regions.go.
	clientsForRegion func(region string) *Provider

	// mu guards warnings and serializes the warnw write. warnf is called from
	// the per-principal goroutines in the IAM scan, so both need it — and the
	// serialized write keeps concurrent warnings from interleaving mid-line.
	mu sync.Mutex
	// warnings is every observation this provider could not complete. See warnf.
	warnings []string
}

// Option configures a Provider at construction.
type Option func(*Provider)

// WithQuiet routes non-fatal provider warnings to io.Discard (used by --quiet).
func WithQuiet(quiet bool) Option {
	return func(p *Provider) {
		if quiet {
			p.warnw = io.Discard
		}
	}
}

// WithRegions restricts regional scans to the named regions (used by --regions).
// Empty means every region enabled for the account.
func WithRegions(regions []string) Option {
	return func(p *Provider) {
		p.regions = append([]string(nil), regions...)
	}
}

// warnf emits a non-fatal warning to warnw (os.Stderr unless --quiet set it to
// io.Discard) and records it as an observation the scan could not complete.
//
// Every warnf call site is somewhere the provider could not see all of what it
// was asked to look at: a paginator that failed partway, a policy that raced
// away, a service whose quotas would not list. That is not cosmetic noise. A
// scan that could not read part of an account must not let the unread part
// report as clean, so the message is retained — Incomplete surfaces it, and the
// exit code reflects it. --quiet silences the stderr copy; it does not make the
// run complete, so the record is kept either way.
//
// Use this for any skip. Never drop an AWS error and return no finding.
// Warnings raised on a region-bound provider are recorded on the root, so a
// region the sweep could not read is reported by the run rather than lost with
// the sub-provider that hit it.
func (p *Provider) warnf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	r := p.root()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.warnings = append(r.warnings, strings.TrimSpace(strings.TrimPrefix(msg, "warn: ")))

	w := r.warnw
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprint(w, msg)
}

// Incomplete returns every observation this provider could not complete during
// the run. A non-empty result means the scan did not see the whole account, so a
// report with no findings is not evidence that there is nothing to find.
//
// Satisfies cloud.IncompleteReporter.
func (p *Provider) Incomplete() []string {
	r := p.root()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.warnings) == 0 {
		return nil
	}
	return append([]string(nil), r.warnings...)
}

// New loads credentials from the default chain and returns a Provider.
func New(ctx context.Context, opts ...Option) (*Provider, error) {
	return NewWithProfile(ctx, "", opts...)
}

// awsHTTPTimeout bounds a single AWS HTTP request; awsOpTimeout bounds a whole
// operation including its retries. Without them an unreachable endpoint would
// hang a scan indefinitely — the command's signal-aware context (cmd.Context())
// lets a user Ctrl-C, but these put a hard ceiling on each call regardless.
const (
	awsHTTPTimeout = 30 * time.Second
	awsOpTimeout   = 60 * time.Second
)

// withOperationTimeout wraps each operation's context with a deadline. Initialize
// runs once per operation, before the retry loop, so the deadline spans every
// attempt.
func withOperationTimeout(d time.Duration) func(*smithymiddleware.Stack) error {
	return func(stack *smithymiddleware.Stack) error {
		return stack.Initialize.Add(smithymiddleware.InitializeMiddlewareFunc(
			"OperationTimeout",
			func(ctx context.Context, in smithymiddleware.InitializeInput, next smithymiddleware.InitializeHandler) (smithymiddleware.InitializeOutput, smithymiddleware.Metadata, error) {
				ctx, cancel := context.WithTimeout(ctx, d)
				defer cancel()
				return next.HandleInitialize(ctx, in)
			},
		), smithymiddleware.Before)
	}
}

// NewWithProfile loads credentials using the named AWS profile. If profile is empty, the default chain is used.
func NewWithProfile(ctx context.Context, profile string, opts ...Option) (*Provider, error) {
	loadOpts := []func(*config.LoadOptions) error{
		// Retry is uniform across every client because every call this provider
		// can make is a read, and a read re-derives its answer from observed
		// state on each attempt. That is the property that makes a retry safe —
		// convergence, not read-ness as such: a mutation may be retried only
		// where it re-derives its work each time, and one that appends,
		// increments, charges or issues never may.
		//
		// Nothing here mutates, and internal/cloud/aws/readonly_test.go fails the
		// build if that stops being true, so a mutating call cannot inherit this
		// policy by being added next to it.
		//
		// Standard mode retries named transient shapes — throttling, 5xx,
		// connection failures — rather than any error, so a permission denial
		// fails on the first attempt and reaches warnf as an incomplete
		// observation instead of being retried five times into the same answer.
		config.WithRetryMaxAttempts(5),
		config.WithRetryMode(awssdk.RetryModeStandard),
		config.WithHTTPClient(awshttp.NewBuildableClient().WithTimeout(awsHTTPTimeout)),
		config.WithAPIOptions([]func(*smithymiddleware.Stack) error{withOperationTimeout(awsOpTimeout)}),
	}
	if profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, err
	}
	p := newFromConfig(cfg)
	// Region-bound providers reuse the loaded credentials and only re-point the
	// region, so a fan-out costs a set of clients rather than a credential
	// resolution per region.
	p.clientsForRegion = func(region string) *Provider {
		rcfg := cfg.Copy()
		rcfg.Region = region
		rp := newFromConfig(rcfg)
		rp.parent = p
		return rp
	}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

// newFromConfig wires every SDK client from one config. Called once for the
// provider itself and once per region by clientsForRegion.
func newFromConfig(cfg awssdk.Config) *Provider {
	return &Provider{
		cfg:          cfg,
		iam:          iam.NewFromConfig(cfg),
		cloudtrail:   cloudtrail.NewFromConfig(cfg),
		ec2:          ec2.NewFromConfig(cfg),
		elbv2:        elasticloadbalancingv2.NewFromConfig(cfg),
		costexplorer: costexplorer.NewFromConfig(cfg),
		s3:           s3.NewFromConfig(cfg),
		s3ForRegion: func(region string) s3API {
			return s3.NewFromConfig(cfg, func(o *s3.Options) {
				o.Region = region
			})
		},
		acm:            acm.NewFromConfig(cfg),
		rds:            rds.NewFromConfig(cfg),
		lambda:         lambda.NewFromConfig(cfg),
		ecs:            ecs.NewFromConfig(cfg),
		ssm:            ssm.NewFromConfig(cfg),
		cloudformation: cloudformation.NewFromConfig(cfg),
		servicequotas:  servicequotas.NewFromConfig(cfg),
		eks:            eks.NewFromConfig(cfg),
		logs:           cloudwatchlogs.NewFromConfig(cfg),
		sqs:            sqs.NewFromConfig(cfg),
		eventbridge:    eventbridge.NewFromConfig(cfg),
		dynamodb:       dynamodb.NewFromConfig(cfg),
		sns:            sns.NewFromConfig(cfg),
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string { return "aws" }

// Detect returns true when AWS credentials are present in the environment.
func (p *Provider) Detect(ctx context.Context) bool {
	envKeys := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_PROFILE",
		"AWS_DEFAULT_REGION",
		"AWS_ROLE_ARN",
	}
	for _, k := range envKeys {
		if os.Getenv(k) != "" {
			return true
		}
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		for _, f := range []string{"/.aws/credentials", "/.aws/config"} {
			if _, err := os.Stat(home + f); err == nil {
				return true
			}
		}
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithHTTPClient(awshttp.NewBuildableClient().WithTimeout(awsHTTPTimeout)))
	if err != nil {
		return false
	}
	_, err = cfg.Credentials.Retrieve(ctx)
	return err == nil
}

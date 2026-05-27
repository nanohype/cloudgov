package aws

import (
	"context"
	"os"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// Provider implements all Matlock provider interfaces for AWS.
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
}

// New loads credentials from the default chain and returns a Provider.
func New(ctx context.Context) (*Provider, error) {
	return NewWithProfile(ctx, "")
}

// NewWithProfile loads credentials using the named AWS profile. If profile is empty, the default chain is used.
func NewWithProfile(ctx context.Context, profile string) (*Provider, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRetryMaxAttempts(5),
		config.WithRetryMode(awssdk.RetryModeStandard),
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
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
	}, nil
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
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return false
	}
	_, err = cfg.Credentials.Retrieve(ctx)
	return err == nil
}

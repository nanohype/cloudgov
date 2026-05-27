package aws

import (
	"context"
	"errors"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithy "github.com/aws/smithy-go"
	"github.com/stxkxs/matlock/internal/cloud"
)

// s3API is the narrow S3 surface used by this package.
type s3API interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error)
	GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error)
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
}

// AuditStorage checks every S3 bucket for public access, encryption, versioning, and logging.
func (p *Provider) AuditStorage(ctx context.Context) ([]cloud.BucketFinding, error) {
	listOut, err := p.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var findings []cloud.BucketFinding
	for _, bucket := range listOut.Buckets {
		name := awssdk.ToString(bucket.Name)
		region, err := p.bucketRegion(ctx, p.s3, name)
		if err != nil {
			region = p.cfg.Region
		}

		regionalClient := p.s3ForRegion(region)

		findings = append(findings, p.checkPublicAccessBlock(ctx, regionalClient, name, region)...)
		findings = append(findings, p.checkEncryption(ctx, regionalClient, name, region)...)
		findings = append(findings, p.checkVersioning(ctx, regionalClient, name, region)...)
		findings = append(findings, p.checkLogging(ctx, regionalClient, name, region)...)
	}
	return findings, nil
}

func (p *Provider) bucketRegion(ctx context.Context, client s3API, bucket string) (string, error) {
	out, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: awssdk.String(bucket)})
	if err != nil {
		return "", fmt.Errorf("get bucket location: %w", err)
	}
	if out.LocationConstraint == "" {
		return "us-east-1", nil
	}
	return string(out.LocationConstraint), nil
}

func (p *Provider) checkPublicAccessBlock(ctx context.Context, client s3API, bucket, region string) []cloud.BucketFinding {
	out, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: awssdk.String(bucket)})
	if err != nil {
		if isS3ErrorCode(err, "NoSuchPublicAccessBlockConfiguration") {
			return []cloud.BucketFinding{{
				Severity:    cloud.SeverityCritical,
				Type:        cloud.BucketPublicAccess,
				Provider:    "aws",
				Bucket:      bucket,
				Region:      region,
				Detail:      "no public access block configuration — bucket may be publicly accessible",
				Remediation: fmt.Sprintf("aws s3api put-public-access-block --bucket %s --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", bucket),
			}}
		}
		return nil
	}
	cfg := out.PublicAccessBlockConfiguration
	if cfg == nil {
		return nil
	}
	if !awssdk.ToBool(cfg.BlockPublicAcls) || !awssdk.ToBool(cfg.IgnorePublicAcls) ||
		!awssdk.ToBool(cfg.BlockPublicPolicy) || !awssdk.ToBool(cfg.RestrictPublicBuckets) {
		return []cloud.BucketFinding{{
			Severity:    cloud.SeverityCritical,
			Type:        cloud.BucketPublicAccess,
			Provider:    "aws",
			Bucket:      bucket,
			Region:      region,
			Detail:      "public access block is not fully enabled",
			Remediation: fmt.Sprintf("aws s3api put-public-access-block --bucket %s --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", bucket),
		}}
	}
	return nil
}

func (p *Provider) checkEncryption(ctx context.Context, client s3API, bucket, region string) []cloud.BucketFinding {
	_, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: awssdk.String(bucket)})
	if err != nil {
		if isS3ErrorCode(err, "ServerSideEncryptionConfigurationNotFoundError") {
			return []cloud.BucketFinding{{
				Severity:    cloud.SeverityHigh,
				Type:        cloud.BucketUnencrypted,
				Provider:    "aws",
				Bucket:      bucket,
				Region:      region,
				Detail:      "default server-side encryption is not configured",
				Remediation: fmt.Sprintf(`aws s3api put-bucket-encryption --bucket %s --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'`, bucket),
			}}
		}
	}
	return nil
}

func (p *Provider) checkVersioning(ctx context.Context, client s3API, bucket, region string) []cloud.BucketFinding {
	out, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: awssdk.String(bucket)})
	if err != nil {
		return nil
	}
	if out.Status != s3types.BucketVersioningStatusEnabled {
		return []cloud.BucketFinding{{
			Severity:    cloud.SeverityMedium,
			Type:        cloud.BucketNoVersioning,
			Provider:    "aws",
			Bucket:      bucket,
			Region:      region,
			Detail:      "versioning is not enabled",
			Remediation: fmt.Sprintf("aws s3api put-bucket-versioning --bucket %s --versioning-configuration Status=Enabled", bucket),
		}}
	}
	return nil
}

func (p *Provider) checkLogging(ctx context.Context, client s3API, bucket, region string) []cloud.BucketFinding {
	out, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: awssdk.String(bucket)})
	if err != nil {
		return nil
	}
	if out.LoggingEnabled == nil {
		return []cloud.BucketFinding{{
			Severity:    cloud.SeverityLow,
			Type:        cloud.BucketNoLogging,
			Provider:    "aws",
			Bucket:      bucket,
			Region:      region,
			Detail:      "access logging is not enabled",
			Remediation: fmt.Sprintf(`aws s3api put-bucket-logging --bucket %s --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"<log-bucket>","TargetPrefix":"%s/"}}'`, bucket, bucket),
		}}
	}
	return nil
}

// isS3ErrorCode returns true if err is an AWS API error with the given code.
func isS3ErrorCode(err error, code string) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == code
	}
	return false
}

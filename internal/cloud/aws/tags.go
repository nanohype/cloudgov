package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stxkxs/matlock/internal/cloud"
)

// rdsAPI is the narrow RDS surface used by this package.
type rdsAPI interface {
	DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

// lambdaAPI is the narrow Lambda surface used by this package.
type lambdaAPI interface {
	ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	ListTags(ctx context.Context, params *lambda.ListTagsInput, optFns ...func(*lambda.Options)) (*lambda.ListTagsOutput, error)
	GetAccountSettings(ctx context.Context, params *lambda.GetAccountSettingsInput, optFns ...func(*lambda.Options)) (*lambda.GetAccountSettingsOutput, error)
	GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

// AuditTags checks EC2 instances, S3 buckets, RDS instances, and Lambda functions
// for missing required tags.
func (p *Provider) AuditTags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	if len(required) == 0 {
		return nil, nil
	}

	var findings []cloud.TagFinding

	ec2Findings, err := p.auditEC2Tags(ctx, required)
	if err != nil {
		return nil, fmt.Errorf("ec2 tags: %w", err)
	}
	findings = append(findings, ec2Findings...)

	s3Findings, err := p.auditS3Tags(ctx, required)
	if err != nil {
		return nil, fmt.Errorf("s3 tags: %w", err)
	}
	findings = append(findings, s3Findings...)

	rdsFindings, err := p.auditRDSTags(ctx, required)
	if err != nil {
		return nil, fmt.Errorf("rds tags: %w", err)
	}
	findings = append(findings, rdsFindings...)

	lambdaFindings, err := p.auditLambdaTags(ctx, required)
	if err != nil {
		return nil, fmt.Errorf("lambda tags: %w", err)
	}
	findings = append(findings, lambdaFindings...)

	return findings, nil
}

func (p *Provider) auditEC2Tags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	pager := ec2.NewDescribeInstancesPaginator(p.ec2, &ec2.DescribeInstancesInput{})

	var findings []cloud.TagFinding
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe instances: %w", err)
		}
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				tagMap := make(map[string]struct{})
				for _, t := range instance.Tags {
					tagMap[awssdk.ToString(t.Key)] = struct{}{}
				}
				missing := missingTags(required, tagMap)
				if len(missing) == 0 {
					continue
				}
				id := awssdk.ToString(instance.InstanceId)
				findings = append(findings, cloud.TagFinding{
					Severity:     cloud.SeverityMedium,
					Provider:     "aws",
					ResourceID:   id,
					ResourceType: "ec2:instance",
					Region:       p.cfg.Region,
					MissingTags:  missing,
					Detail:       fmt.Sprintf("instance %s missing tags: %v", id, missing),
				})
			}
		}
	}
	return findings, nil
}

func (p *Provider) auditS3Tags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	listOut, err := p.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var findings []cloud.TagFinding
	for _, bucket := range listOut.Buckets {
		name := awssdk.ToString(bucket.Name)
		region, err := p.bucketRegion(ctx, p.s3, name)
		if err != nil {
			region = p.cfg.Region
		}

		regionalClient := p.s3ForRegion(region)

		tagMap := make(map[string]struct{})
		tagging, err := regionalClient.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: awssdk.String(name)})
		if err == nil {
			for _, t := range tagging.TagSet {
				tagMap[awssdk.ToString(t.Key)] = struct{}{}
			}
		}

		missing := missingTags(required, tagMap)
		if len(missing) == 0 {
			continue
		}
		findings = append(findings, cloud.TagFinding{
			Severity:     cloud.SeverityMedium,
			Provider:     "aws",
			ResourceID:   name,
			ResourceType: "s3:bucket",
			Region:       region,
			MissingTags:  missing,
			Detail:       fmt.Sprintf("bucket %s missing tags: %v", name, missing),
		})
	}
	return findings, nil
}

func (p *Provider) auditRDSTags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	pager := rds.NewDescribeDBInstancesPaginator(p.rds, &rds.DescribeDBInstancesInput{})

	var findings []cloud.TagFinding
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe db instances: %w", err)
		}
		for _, db := range page.DBInstances {
			tagMap := make(map[string]struct{})
			for _, t := range db.TagList {
				tagMap[awssdk.ToString(t.Key)] = struct{}{}
			}
			missing := missingTags(required, tagMap)
			if len(missing) == 0 {
				continue
			}
			id := awssdk.ToString(db.DBInstanceIdentifier)
			findings = append(findings, cloud.TagFinding{
				Severity:     cloud.SeverityMedium,
				Provider:     "aws",
				ResourceID:   id,
				ResourceType: "rds:db",
				Region:       p.cfg.Region,
				MissingTags:  missing,
				Detail:       fmt.Sprintf("rds instance %s missing tags: %v", id, missing),
			})
		}
	}
	return findings, nil
}

func (p *Provider) auditLambdaTags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	var findings []cloud.TagFinding
	var marker *string
	for {
		page, err := p.lambda.ListFunctions(ctx, &lambda.ListFunctionsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("list functions: %w", err)
		}
		for _, fn := range page.Functions {
			if fn.FunctionArn == nil {
				continue
			}
			tagsOut, err := p.lambda.ListTags(ctx, &lambda.ListTagsInput{
				Resource: fn.FunctionArn,
			})
			if err != nil {
				continue
			}
			tagMap := make(map[string]struct{})
			for k := range tagsOut.Tags {
				tagMap[k] = struct{}{}
			}
			missing := missingTags(required, tagMap)
			if len(missing) == 0 {
				continue
			}
			name := awssdk.ToString(fn.FunctionName)
			findings = append(findings, cloud.TagFinding{
				Severity:     cloud.SeverityMedium,
				Provider:     "aws",
				ResourceID:   name,
				ResourceType: "lambda:function",
				Region:       p.cfg.Region,
				MissingTags:  missing,
				Detail:       fmt.Sprintf("lambda function %s missing tags: %v", name, missing),
			})
		}
		if page.NextMarker == nil {
			break
		}
		marker = page.NextMarker
	}
	return findings, nil
}

func missingTags(required []string, have map[string]struct{}) []string {
	var missing []string
	for _, tag := range required {
		if _, ok := have[tag]; !ok {
			missing = append(missing, tag)
		}
	}
	return missing
}

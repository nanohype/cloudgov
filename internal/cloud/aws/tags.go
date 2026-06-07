package aws

import (
	"context"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/nanohype/cloudgov/internal/cloud"
)

// rdsAPI is the narrow RDS surface used by this package.
type rdsAPI interface {
	DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

// dynamodbAPI is the narrow DynamoDB surface used by this package.
type dynamodbAPI interface {
	ListTables(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error)
	DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	ListTagsOfResource(ctx context.Context, params *dynamodb.ListTagsOfResourceInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTagsOfResourceOutput, error)
}

// snsAPI is the narrow SNS surface used by this package.
type snsAPI interface {
	ListTopics(ctx context.Context, params *sns.ListTopicsInput, optFns ...func(*sns.Options)) (*sns.ListTopicsOutput, error)
	ListTagsForResource(ctx context.Context, params *sns.ListTagsForResourceInput, optFns ...func(*sns.Options)) (*sns.ListTagsForResourceOutput, error)
}

// lambdaAPI is the narrow Lambda surface used by this package.
type lambdaAPI interface {
	ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	ListTags(ctx context.Context, params *lambda.ListTagsInput, optFns ...func(*lambda.Options)) (*lambda.ListTagsOutput, error)
	GetAccountSettings(ctx context.Context, params *lambda.GetAccountSettingsInput, optFns ...func(*lambda.Options)) (*lambda.GetAccountSettingsOutput, error)
	GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

// AuditTags checks EC2 instances, S3 buckets, RDS instances, Lambda functions, ECS
// clusters, EKS clusters, DynamoDB tables, SNS topics, and SQS queues for missing
// required tags.
func (p *Provider) AuditTags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	if len(required) == 0 {
		return nil, nil
	}

	type auditor struct {
		name string
		fn   func(context.Context, []string) ([]cloud.TagFinding, error)
	}
	auditors := []auditor{
		{"ec2", p.auditEC2Tags},
		{"s3", p.auditS3Tags},
		{"rds", p.auditRDSTags},
		{"lambda", p.auditLambdaTags},
		{"ecs", p.auditECSTags},
		{"eks", p.auditEKSTags},
		{"dynamodb", p.auditDynamoDBTags},
		{"sns", p.auditSNSTags},
		{"sqs", p.auditSQSTags},
	}

	var findings []cloud.TagFinding
	for _, a := range auditors {
		got, err := a.fn(ctx, required)
		if err != nil {
			return nil, fmt.Errorf("%s tags: %w", a.name, err)
		}
		findings = append(findings, got...)
	}
	return findings, nil
}

func (p *Provider) auditEC2Tags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	if p.ec2 == nil {
		return nil, nil
	}
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
	if p.s3 == nil {
		return nil, nil
	}
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
	if p.rds == nil {
		return nil, nil
	}
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
	if p.lambda == nil {
		return nil, nil
	}
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

func (p *Provider) auditECSTags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	if p.ecs == nil {
		return nil, nil
	}
	var findings []cloud.TagFinding
	var token *string
	for {
		listed, err := p.ecs.ListClusters(ctx, &ecs.ListClustersInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("list clusters: %w", err)
		}
		if len(listed.ClusterArns) > 0 {
			desc, err := p.ecs.DescribeClusters(ctx, &ecs.DescribeClustersInput{
				Clusters: listed.ClusterArns,
				Include:  []ecstypes.ClusterField{ecstypes.ClusterFieldTags},
			})
			if err != nil {
				return nil, fmt.Errorf("describe clusters: %w", err)
			}
			for _, c := range desc.Clusters {
				tagMap := make(map[string]struct{}, len(c.Tags))
				for _, t := range c.Tags {
					tagMap[awssdk.ToString(t.Key)] = struct{}{}
				}
				missing := missingTags(required, tagMap)
				if len(missing) == 0 {
					continue
				}
				name := awssdk.ToString(c.ClusterName)
				findings = append(findings, cloud.TagFinding{
					Severity:     cloud.SeverityMedium,
					Provider:     "aws",
					ResourceID:   name,
					ResourceType: "ecs:cluster",
					Region:       p.cfg.Region,
					MissingTags:  missing,
					Detail:       fmt.Sprintf("ecs cluster %s missing tags: %v", name, missing),
				})
			}
		}
		if listed.NextToken == nil {
			break
		}
		token = listed.NextToken
	}
	return findings, nil
}

func (p *Provider) auditEKSTags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	if p.eks == nil {
		return nil, nil
	}
	var findings []cloud.TagFinding
	var token *string
	for {
		listed, err := p.eks.ListClusters(ctx, &eks.ListClustersInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("list clusters: %w", err)
		}
		for _, name := range listed.Clusters {
			desc, err := p.eks.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: awssdk.String(name)})
			if err != nil || desc.Cluster == nil {
				continue
			}
			tagMap := make(map[string]struct{}, len(desc.Cluster.Tags))
			for k := range desc.Cluster.Tags {
				tagMap[k] = struct{}{}
			}
			missing := missingTags(required, tagMap)
			if len(missing) == 0 {
				continue
			}
			findings = append(findings, cloud.TagFinding{
				Severity:     cloud.SeverityMedium,
				Provider:     "aws",
				ResourceID:   name,
				ResourceType: "eks:cluster",
				Region:       p.cfg.Region,
				MissingTags:  missing,
				Detail:       fmt.Sprintf("eks cluster %s missing tags: %v", name, missing),
			})
		}
		if listed.NextToken == nil {
			break
		}
		token = listed.NextToken
	}
	return findings, nil
}

func (p *Provider) auditDynamoDBTags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	if p.dynamodb == nil {
		return nil, nil
	}
	var findings []cloud.TagFinding
	var start *string
	for {
		listed, err := p.dynamodb.ListTables(ctx, &dynamodb.ListTablesInput{ExclusiveStartTableName: start})
		if err != nil {
			return nil, fmt.Errorf("list tables: %w", err)
		}
		for _, name := range listed.TableNames {
			desc, err := p.dynamodb.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: awssdk.String(name)})
			if err != nil || desc.Table == nil || desc.Table.TableArn == nil {
				continue
			}
			tagMap, err := p.dynamodbTableTags(ctx, awssdk.ToString(desc.Table.TableArn))
			if err != nil {
				continue
			}
			missing := missingTags(required, tagMap)
			if len(missing) == 0 {
				continue
			}
			findings = append(findings, cloud.TagFinding{
				Severity:     cloud.SeverityMedium,
				Provider:     "aws",
				ResourceID:   name,
				ResourceType: "dynamodb:table",
				Region:       p.cfg.Region,
				MissingTags:  missing,
				Detail:       fmt.Sprintf("dynamodb table %s missing tags: %v", name, missing),
			})
		}
		if listed.LastEvaluatedTableName == nil {
			break
		}
		start = listed.LastEvaluatedTableName
	}
	return findings, nil
}

// dynamodbTableTags returns the set of tag keys on a DynamoDB table (tags are a
// separate API call, paginated).
func (p *Provider) dynamodbTableTags(ctx context.Context, arn string) (map[string]struct{}, error) {
	tagMap := make(map[string]struct{})
	var token *string
	for {
		out, err := p.dynamodb.ListTagsOfResource(ctx, &dynamodb.ListTagsOfResourceInput{
			ResourceArn: awssdk.String(arn),
			NextToken:   token,
		})
		if err != nil {
			return nil, err
		}
		for _, t := range out.Tags {
			tagMap[awssdk.ToString(t.Key)] = struct{}{}
		}
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}
	return tagMap, nil
}

func (p *Provider) auditSNSTags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	if p.sns == nil {
		return nil, nil
	}
	var findings []cloud.TagFinding
	var token *string
	for {
		listed, err := p.sns.ListTopics(ctx, &sns.ListTopicsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("list topics: %w", err)
		}
		for _, topic := range listed.Topics {
			arn := awssdk.ToString(topic.TopicArn)
			if arn == "" {
				continue
			}
			tagsOut, err := p.sns.ListTagsForResource(ctx, &sns.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)})
			if err != nil {
				continue
			}
			tagMap := make(map[string]struct{}, len(tagsOut.Tags))
			for _, t := range tagsOut.Tags {
				tagMap[awssdk.ToString(t.Key)] = struct{}{}
			}
			missing := missingTags(required, tagMap)
			if len(missing) == 0 {
				continue
			}
			name := arnTailAfter(arn, ":")
			findings = append(findings, cloud.TagFinding{
				Severity:     cloud.SeverityMedium,
				Provider:     "aws",
				ResourceID:   name,
				ResourceType: "sns:topic",
				Region:       p.cfg.Region,
				MissingTags:  missing,
				Detail:       fmt.Sprintf("sns topic %s missing tags: %v", name, missing),
			})
		}
		if listed.NextToken == nil {
			break
		}
		token = listed.NextToken
	}
	return findings, nil
}

func (p *Provider) auditSQSTags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	if p.sqs == nil {
		return nil, nil
	}
	var findings []cloud.TagFinding
	var token *string
	for {
		listed, err := p.sqs.ListQueues(ctx, &sqs.ListQueuesInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("list queues: %w", err)
		}
		for _, url := range listed.QueueUrls {
			tagsOut, err := p.sqs.ListQueueTags(ctx, &sqs.ListQueueTagsInput{QueueUrl: awssdk.String(url)})
			if err != nil {
				continue
			}
			tagMap := make(map[string]struct{}, len(tagsOut.Tags))
			for k := range tagsOut.Tags {
				tagMap[k] = struct{}{}
			}
			missing := missingTags(required, tagMap)
			if len(missing) == 0 {
				continue
			}
			name := arnTailAfter(url, "/")
			findings = append(findings, cloud.TagFinding{
				Severity:     cloud.SeverityMedium,
				Provider:     "aws",
				ResourceID:   name,
				ResourceType: "sqs:queue",
				Region:       p.cfg.Region,
				MissingTags:  missing,
				Detail:       fmt.Sprintf("sqs queue %s missing tags: %v", name, missing),
			})
		}
		if listed.NextToken == nil {
			break
		}
		token = listed.NextToken
	}
	return findings, nil
}

// arnTailAfter returns the substring after the last occurrence of sep (the topic
// name in an SNS ARN, or the queue name in an SQS URL), or the input unchanged when
// sep is absent.
func arnTailAfter(s, sep string) string {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[i+len(sep):]
	}
	return s
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

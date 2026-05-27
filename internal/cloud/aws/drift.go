package aws

import (
	"context"
	"errors"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithy "github.com/aws/smithy-go"
	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/drift"
)

// SupportedResourceTypes returns the Terraform resource types this provider can check for drift.
func (p *Provider) SupportedResourceTypes() []string {
	return []string{
		"aws_security_group",
		"aws_iam_policy",
		"aws_s3_bucket",
		"aws_s3_bucket_public_access_block",
		"aws_instance",
		"aws_db_instance",
		"aws_lb",
	}
}

// CheckDrift compares live AWS state against the provided Terraform attributes.
func (p *Provider) CheckDrift(ctx context.Context, resourceType, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	switch resourceType {
	case "aws_security_group":
		return p.checkSGDrift(ctx, resourceID, attrs)
	case "aws_iam_policy":
		return p.checkIAMPolicyDrift(ctx, resourceID, attrs)
	case "aws_s3_bucket":
		return p.checkS3BucketDrift(ctx, resourceID, attrs)
	case "aws_s3_bucket_public_access_block":
		return p.checkS3PublicAccessBlockDrift(ctx, resourceID, attrs)
	case "aws_instance":
		return p.checkEC2InstanceDrift(ctx, resourceID, attrs)
	case "aws_db_instance":
		return p.checkRDSInstanceDrift(ctx, resourceID, attrs)
	case "aws_lb":
		return p.checkELBDrift(ctx, resourceID, attrs)
	default:
		return cloud.DriftResult{
			ResourceType: resourceType,
			ResourceID:   resourceID,
			Status:       cloud.DriftError,
			Detail:       "unsupported resource type",
		}, nil
	}
}

func (p *Provider) checkSGDrift(ctx context.Context, sgID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	out, err := p.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{{
			Name:   awssdk.String("group-id"),
			Values: []string{sgID},
		}},
	})
	if err != nil {
		return cloud.DriftResult{}, fmt.Errorf("describe security group %s: %w", sgID, err)
	}
	if len(out.SecurityGroups) == 0 {
		return cloud.DriftResult{
			ResourceType: "aws_security_group",
			ResourceID:   sgID,
			Status:       cloud.DriftDeleted,
			Detail:       "security group not found in AWS",
		}, nil
	}

	sg := out.SecurityGroups[0]
	actual := map[string]interface{}{
		"name":        awssdk.ToString(sg.GroupName),
		"description": awssdk.ToString(sg.Description),
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"name", "description"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "aws_security_group",
			ResourceID:   sgID,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "aws_security_group",
		ResourceID:   sgID,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkIAMPolicyDrift(ctx context.Context, policyARN string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	out, err := p.iam.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: awssdk.String(policyARN),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchEntity" {
			return cloud.DriftResult{
				ResourceType: "aws_iam_policy",
				ResourceID:   policyARN,
				Status:       cloud.DriftDeleted,
				Detail:       "IAM policy not found in AWS",
			}, nil
		}
		return cloud.DriftResult{}, fmt.Errorf("get policy %s: %w", policyARN, err)
	}

	actual := map[string]interface{}{
		"description": awssdk.ToString(out.Policy.Description),
		"path":        awssdk.ToString(out.Policy.Path),
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"description", "path"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "aws_iam_policy",
			ResourceID:   policyARN,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "aws_iam_policy",
		ResourceID:   policyARN,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkS3BucketDrift(ctx context.Context, bucketName string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	// Check if bucket exists
	_, err := p.s3.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: awssdk.String(bucketName),
	})
	if err != nil {
		return cloud.DriftResult{
			ResourceType: "aws_s3_bucket",
			ResourceID:   bucketName,
			Status:       cloud.DriftDeleted,
			Detail:       "S3 bucket not found or not accessible",
		}, nil
	}

	// Check versioning
	versionOut, err := p.s3.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: awssdk.String(bucketName),
	})
	if err != nil {
		return cloud.DriftResult{}, fmt.Errorf("get bucket versioning %s: %w", bucketName, err)
	}

	actual := map[string]interface{}{
		"bucket": bucketName,
	}
	if versionOut.Status == "Enabled" {
		actual["versioning_enabled"] = "true"
	} else {
		actual["versioning_enabled"] = "false"
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"bucket"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "aws_s3_bucket",
			ResourceID:   bucketName,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "aws_s3_bucket",
		ResourceID:   bucketName,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkS3PublicAccessBlockDrift(ctx context.Context, bucketName string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	out, err := p.s3.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: awssdk.String(bucketName),
	})
	if err != nil {
		if isS3ErrorCode(err, "NoSuchPublicAccessBlockConfiguration") {
			return cloud.DriftResult{
				ResourceType: "aws_s3_bucket_public_access_block",
				ResourceID:   bucketName,
				Status:       cloud.DriftDeleted,
				Detail:       "public access block configuration not found",
			}, nil
		}
		return cloud.DriftResult{}, fmt.Errorf("get public access block %s: %w", bucketName, err)
	}

	cfg := out.PublicAccessBlockConfiguration
	actual := map[string]interface{}{
		"block_public_acls":       fmt.Sprintf("%v", awssdk.ToBool(cfg.BlockPublicAcls)),
		"block_public_policy":     fmt.Sprintf("%v", awssdk.ToBool(cfg.BlockPublicPolicy)),
		"ignore_public_acls":      fmt.Sprintf("%v", awssdk.ToBool(cfg.IgnorePublicAcls)),
		"restrict_public_buckets": fmt.Sprintf("%v", awssdk.ToBool(cfg.RestrictPublicBuckets)),
	}

	fields := []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}
	diffs := drift.CompareAttributes(attrs, actual, fields)
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "aws_s3_bucket_public_access_block",
			ResourceID:   bucketName,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "aws_s3_bucket_public_access_block",
		ResourceID:   bucketName,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkEC2InstanceDrift(ctx context.Context, instanceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	out, err := p.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidInstanceID.NotFound" {
			return cloud.DriftResult{
				ResourceType: "aws_instance",
				ResourceID:   instanceID,
				Status:       cloud.DriftDeleted,
				Detail:       "EC2 instance not found in AWS",
			}, nil
		}
		return cloud.DriftResult{}, fmt.Errorf("describe instance %s: %w", instanceID, err)
	}
	if len(out.Reservations) == 0 || len(out.Reservations[0].Instances) == 0 {
		return cloud.DriftResult{
			ResourceType: "aws_instance",
			ResourceID:   instanceID,
			Status:       cloud.DriftDeleted,
			Detail:       "EC2 instance not found in AWS",
		}, nil
	}

	inst := out.Reservations[0].Instances[0]
	actual := map[string]interface{}{
		"instance_type": string(inst.InstanceType),
		"key_name":      awssdk.ToString(inst.KeyName),
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"instance_type", "key_name"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "aws_instance",
			ResourceID:   instanceID,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "aws_instance",
		ResourceID:   instanceID,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkRDSInstanceDrift(ctx context.Context, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	// resourceID may be the DB identifier or an ARN
	identifier := resourceID
	if name, ok := attrs["identifier"]; ok {
		if s, ok := name.(string); ok && s != "" {
			identifier = s
		}
	}

	out, err := p.rds.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: awssdk.String(identifier),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "DBInstanceNotFound" {
			return cloud.DriftResult{
				ResourceType: "aws_db_instance",
				ResourceID:   resourceID,
				Status:       cloud.DriftDeleted,
				Detail:       "RDS instance not found in AWS",
			}, nil
		}
		return cloud.DriftResult{}, fmt.Errorf("describe db instance %s: %w", identifier, err)
	}
	if len(out.DBInstances) == 0 {
		return cloud.DriftResult{
			ResourceType: "aws_db_instance",
			ResourceID:   resourceID,
			Status:       cloud.DriftDeleted,
			Detail:       "RDS instance not found in AWS",
		}, nil
	}

	db := out.DBInstances[0]
	actual := map[string]interface{}{
		"instance_class":      awssdk.ToString(db.DBInstanceClass),
		"engine_version":      awssdk.ToString(db.EngineVersion),
		"multi_az":            fmt.Sprintf("%v", db.MultiAZ),
		"deletion_protection": fmt.Sprintf("%v", db.DeletionProtection),
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"instance_class", "engine_version", "multi_az", "deletion_protection"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "aws_db_instance",
			ResourceID:   resourceID,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "aws_db_instance",
		ResourceID:   resourceID,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkELBDrift(ctx context.Context, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	out, err := p.elbv2.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{
		LoadBalancerArns: []string{resourceID},
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "LoadBalancerNotFound" {
			return cloud.DriftResult{
				ResourceType: "aws_lb",
				ResourceID:   resourceID,
				Status:       cloud.DriftDeleted,
				Detail:       "load balancer not found in AWS",
			}, nil
		}
		return cloud.DriftResult{}, fmt.Errorf("describe load balancer %s: %w", resourceID, err)
	}
	if len(out.LoadBalancers) == 0 {
		return cloud.DriftResult{
			ResourceType: "aws_lb",
			ResourceID:   resourceID,
			Status:       cloud.DriftDeleted,
			Detail:       "load balancer not found in AWS",
		}, nil
	}

	lb := out.LoadBalancers[0]
	actual := map[string]interface{}{
		"load_balancer_type": string(lb.Type),
		"internal":           fmt.Sprintf("%v", lb.Scheme == "internal"),
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"load_balancer_type", "internal"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "aws_lb",
			ResourceID:   resourceID,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "aws_lb",
		ResourceID:   resourceID,
		Status:       cloud.DriftInSync,
	}, nil
}

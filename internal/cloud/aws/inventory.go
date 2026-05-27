package aws

import (
	"context"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stxkxs/matlock/internal/cloud"
)

// ecsAPI is the narrow ECS surface used by this package.
type ecsAPI interface {
	ListClusters(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	DescribeClusters(ctx context.Context, params *ecs.DescribeClustersInput, optFns ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error)
	ListTaskDefinitions(ctx context.Context, params *ecs.ListTaskDefinitionsInput, optFns ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error)
	DescribeTaskDefinition(ctx context.Context, params *ecs.DescribeTaskDefinitionInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}

// ListResources lists AWS resources for inventory.
func (p *Provider) ListResources(ctx context.Context, typeFilter []string) ([]cloud.InventoryResource, error) {
	filter := make(map[string]bool)
	for _, t := range typeFilter {
		filter[strings.ToLower(t)] = true
	}
	all := len(filter) == 0

	var resources []cloud.InventoryResource

	if all || filter["ec2"] || filter["ec2:instance"] {
		r, err := p.listEC2Instances(ctx)
		if err != nil {
			return nil, fmt.Errorf("list ec2 instances: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["s3"] || filter["s3:bucket"] {
		r, err := p.listS3Buckets(ctx)
		if err != nil {
			return nil, fmt.Errorf("list s3 buckets: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["lambda"] || filter["lambda:function"] {
		r, err := p.listLambdaFunctions(ctx)
		if err != nil {
			return nil, fmt.Errorf("list lambda functions: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["ebs"] || filter["ebs:volume"] {
		r, err := p.listEBSVolumes(ctx)
		if err != nil {
			return nil, fmt.Errorf("list ebs volumes: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["rds"] || filter["rds:db"] {
		r, err := p.listRDSInstances(ctx)
		if err != nil {
			return nil, fmt.Errorf("list rds instances: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["ecs"] || filter["ecs:cluster"] {
		r, err := p.listECSClusters(ctx)
		if err != nil {
			return nil, fmt.Errorf("list ecs clusters: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["elb"] || filter["elb:loadbalancer"] {
		r, err := p.listELBLoadBalancers(ctx)
		if err != nil {
			return nil, fmt.Errorf("list elb load balancers: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["iam"] || filter["iam:role"] {
		r, err := p.listIAMRoles(ctx)
		if err != nil {
			return nil, fmt.Errorf("list iam roles: %w", err)
		}
		resources = append(resources, r...)
	}

	return resources, nil
}

func (p *Provider) listEC2Instances(ctx context.Context) ([]cloud.InventoryResource, error) {
	var resources []cloud.InventoryResource

	paginator := ec2.NewDescribeInstancesPaginator(p.ec2, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return resources, fmt.Errorf("describe instances: %w", err)
		}
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				name := ec2TagValue(inst.Tags, "Name")
				id := awssdk.ToString(inst.InstanceId)
				status := string(inst.State.Name)
				tags := ec2TagsToMap(inst.Tags)
				r := cloud.InventoryResource{
					Kind:     cloud.ResourceCompute,
					Type:     "ec2:instance",
					ID:       id,
					Name:     name,
					Provider: "aws",
					Region:   p.cfg.Region,
					Tags:     tags,
					Status:   status,
				}
				if inst.LaunchTime != nil {
					t := *inst.LaunchTime
					r.CreatedAt = &t
				}
				resources = append(resources, r)
			}
		}
	}
	return resources, nil
}

func (p *Provider) listS3Buckets(ctx context.Context) ([]cloud.InventoryResource, error) {
	out, err := p.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var resources []cloud.InventoryResource
	for _, b := range out.Buckets {
		name := awssdk.ToString(b.Name)
		r := cloud.InventoryResource{
			Kind:     cloud.ResourceStorage,
			Type:     "s3:bucket",
			ID:       name,
			Name:     name,
			Provider: "aws",
			Region:   p.cfg.Region,
		}
		if b.CreationDate != nil {
			t := *b.CreationDate
			r.CreatedAt = &t
		}
		resources = append(resources, r)
	}
	return resources, nil
}

func (p *Provider) listLambdaFunctions(ctx context.Context) ([]cloud.InventoryResource, error) {
	var resources []cloud.InventoryResource

	var marker *string
	for {
		out, err := p.lambda.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return resources, fmt.Errorf("list functions: %w", err)
		}
		for _, fn := range out.Functions {
			name := awssdk.ToString(fn.FunctionName)
			resources = append(resources, cloud.InventoryResource{
				Kind:     cloud.ResourceServerless,
				Type:     "lambda:function",
				ID:       awssdk.ToString(fn.FunctionArn),
				Name:     name,
				Provider: "aws",
				Region:   p.cfg.Region,
				Status:   string(fn.State),
			})
		}
		if out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}
	return resources, nil
}

func (p *Provider) listEBSVolumes(ctx context.Context) ([]cloud.InventoryResource, error) {
	var resources []cloud.InventoryResource

	paginator := ec2.NewDescribeVolumesPaginator(p.ec2, &ec2.DescribeVolumesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return resources, fmt.Errorf("describe volumes: %w", err)
		}
		for _, vol := range page.Volumes {
			name := ec2TagValue(vol.Tags, "Name")
			id := awssdk.ToString(vol.VolumeId)
			r := cloud.InventoryResource{
				Kind:     cloud.ResourceStorage,
				Type:     "ebs:volume",
				ID:       id,
				Name:     name,
				Provider: "aws",
				Region:   p.cfg.Region,
				Tags:     ec2TagsToMap(vol.Tags),
				Status:   string(vol.State),
			}
			if vol.CreateTime != nil {
				t := *vol.CreateTime
				r.CreatedAt = &t
			}
			resources = append(resources, r)
		}
	}
	return resources, nil
}

func (p *Provider) listRDSInstances(ctx context.Context) ([]cloud.InventoryResource, error) {
	var resources []cloud.InventoryResource

	paginator := rds.NewDescribeDBInstancesPaginator(p.rds, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return resources, fmt.Errorf("describe db instances: %w", err)
		}
		for _, db := range page.DBInstances {
			id := awssdk.ToString(db.DBInstanceIdentifier)
			r := cloud.InventoryResource{
				Kind:     cloud.ResourceDatabase,
				Type:     "rds:db",
				ID:       awssdk.ToString(db.DBInstanceArn),
				Name:     id,
				Provider: "aws",
				Region:   p.cfg.Region,
				Status:   awssdk.ToString(db.DBInstanceStatus),
			}
			if db.InstanceCreateTime != nil {
				t := *db.InstanceCreateTime
				r.CreatedAt = &t
			}
			resources = append(resources, r)
		}
	}
	return resources, nil
}

func (p *Provider) listECSClusters(ctx context.Context) ([]cloud.InventoryResource, error) {
	var resources []cloud.InventoryResource

	var nextToken *string
	for {
		listOut, err := p.ecs.ListClusters(ctx, &ecs.ListClustersInput{NextToken: nextToken})
		if err != nil {
			return resources, fmt.Errorf("list ecs clusters: %w", err)
		}
		if len(listOut.ClusterArns) == 0 {
			break
		}

		descOut, err := p.ecs.DescribeClusters(ctx, &ecs.DescribeClustersInput{
			Clusters: listOut.ClusterArns,
		})
		if err != nil {
			return resources, fmt.Errorf("describe ecs clusters: %w", err)
		}
		for _, c := range descOut.Clusters {
			arn := awssdk.ToString(c.ClusterArn)
			name := awssdk.ToString(c.ClusterName)
			resources = append(resources, cloud.InventoryResource{
				Kind:     cloud.ResourceContainer,
				Type:     "ecs:cluster",
				ID:       arn,
				Name:     name,
				Provider: "aws",
				Region:   p.cfg.Region,
				Status:   awssdk.ToString(c.Status),
			})
		}

		if listOut.NextToken == nil {
			break
		}
		nextToken = listOut.NextToken
	}
	return resources, nil
}

func (p *Provider) listELBLoadBalancers(ctx context.Context) ([]cloud.InventoryResource, error) {
	var resources []cloud.InventoryResource

	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(p.elbv2, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return resources, fmt.Errorf("describe load balancers: %w", err)
		}
		for _, lb := range page.LoadBalancers {
			r := cloud.InventoryResource{
				Kind:     cloud.ResourceLoadBalancer,
				Type:     "elb:loadbalancer",
				ID:       awssdk.ToString(lb.LoadBalancerArn),
				Name:     awssdk.ToString(lb.LoadBalancerName),
				Provider: "aws",
				Region:   p.cfg.Region,
			}
			if lb.State != nil {
				r.Status = string(lb.State.Code)
			}
			if lb.CreatedTime != nil {
				t := *lb.CreatedTime
				r.CreatedAt = &t
			}
			resources = append(resources, r)
		}
	}
	return resources, nil
}

func (p *Provider) listIAMRoles(ctx context.Context) ([]cloud.InventoryResource, error) {
	var resources []cloud.InventoryResource

	paginator := iam.NewListRolesPaginator(p.iam, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return resources, fmt.Errorf("list iam roles: %w", err)
		}
		for _, role := range page.Roles {
			r := cloud.InventoryResource{
				Kind:     cloud.ResourceIAM,
				Type:     "iam:role",
				ID:       awssdk.ToString(role.Arn),
				Name:     awssdk.ToString(role.RoleName),
				Provider: "aws",
				Region:   "global",
			}
			if role.CreateDate != nil {
				t := *role.CreateDate
				r.CreatedAt = &t
			}
			resources = append(resources, r)
		}
	}
	return resources, nil
}

func ec2TagValue(tags []ec2types.Tag, key string) string {
	for _, t := range tags {
		if awssdk.ToString(t.Key) == key {
			return awssdk.ToString(t.Value)
		}
	}
	return ""
}

func ec2TagsToMap(tags []ec2types.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return m
}

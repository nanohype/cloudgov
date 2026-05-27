package aws

import (
	"context"
	"fmt"
	"os"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/stxkxs/matlock/internal/cloud"
)

// ec2API is the narrow EC2 surface used by this package. Extend it (do not
// declare a parallel interface) when other files need additional methods.
type ec2API interface {
	DescribeVolumes(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	DescribeAddresses(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeInstanceAttribute(ctx context.Context, params *ec2.DescribeInstanceAttributeInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstanceAttributeOutput, error)
	DescribeVpcs(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeInternetGateways(ctx context.Context, params *ec2.DescribeInternetGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error)
}

// elbv2API is the narrow ELBv2 surface used by this package.
type elbv2API interface {
	DescribeLoadBalancers(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error)
	DescribeTargetGroups(ctx context.Context, params *elasticloadbalancingv2.DescribeTargetGroupsInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error)
	DescribeTargetHealth(ctx context.Context, params *elasticloadbalancingv2.DescribeTargetHealthInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetHealthOutput, error)
}

// ListOrphans returns unused AWS resources across the configured region.
func (p *Provider) ListOrphans(ctx context.Context) ([]cloud.OrphanResource, error) {
	var orphans []cloud.OrphanResource

	disks, err := p.orphanDisks(ctx)
	if err != nil {
		return nil, fmt.Errorf("orphan disks: %w", err)
	}
	orphans = append(orphans, disks...)

	ips, err := p.orphanIPs(ctx)
	if err != nil {
		return nil, fmt.Errorf("orphan IPs: %w", err)
	}
	orphans = append(orphans, ips...)

	lbs, err := p.orphanLoadBalancers(ctx)
	if err != nil {
		return nil, fmt.Errorf("orphan load balancers: %w", err)
	}
	orphans = append(orphans, lbs...)

	return orphans, nil
}

// orphanDisks finds EBS volumes that are not attached to any instance.
func (p *Provider) orphanDisks(ctx context.Context) ([]cloud.OrphanResource, error) {
	pager := ec2.NewDescribeVolumesPaginator(p.ec2, &ec2.DescribeVolumesInput{
		Filters: []ec2types.Filter{{
			Name:   awssdk.String("status"),
			Values: []string{"available"},
		}},
	})

	var orphans []cloud.OrphanResource
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: describe volumes page: %v\n", err)
			break
		}
		for _, v := range page.Volumes {
			name := volumeName(v)
			sizeGB := int32(0)
			if v.Size != nil {
				sizeGB = *v.Size
			}
			// Rough cost estimate: $0.10/GB-month for gp2/gp3
			cost := float64(sizeGB) * 0.10
			orphans = append(orphans, cloud.OrphanResource{
				Kind:        cloud.OrphanDisk,
				ID:          awssdk.ToString(v.VolumeId),
				Name:        name,
				Region:      p.cfg.Region,
				Provider:    "aws",
				MonthlyCost: cost,
				Detail:      fmt.Sprintf("%d GiB %s, state: available", sizeGB, v.VolumeType),
			})
		}
	}
	return orphans, nil
}

func volumeName(v ec2types.Volume) string {
	for _, tag := range v.Tags {
		if awssdk.ToString(tag.Key) == "Name" {
			return awssdk.ToString(tag.Value)
		}
	}
	return awssdk.ToString(v.VolumeId)
}

// orphanIPs finds Elastic IPs that are not associated with any resource.
func (p *Provider) orphanIPs(ctx context.Context) ([]cloud.OrphanResource, error) {
	out, err := p.ec2.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, fmt.Errorf("describe addresses: %w", err)
	}

	var orphans []cloud.OrphanResource
	for _, addr := range out.Addresses {
		if addr.AssociationId != nil {
			continue // in use
		}
		orphans = append(orphans, cloud.OrphanResource{
			Kind:        cloud.OrphanIP,
			ID:          awssdk.ToString(addr.AllocationId),
			Name:        awssdk.ToString(addr.PublicIp),
			Region:      p.cfg.Region,
			Provider:    "aws",
			MonthlyCost: 3.65, // ~$0.005/hr for unassociated EIPs
			Detail:      fmt.Sprintf("EIP %s is unassociated", awssdk.ToString(addr.PublicIp)),
		})
	}
	return orphans, nil
}

// orphanLoadBalancers finds ALBs/NLBs with no registered targets.
func (p *Provider) orphanLoadBalancers(ctx context.Context) ([]cloud.OrphanResource, error) {
	lbPager := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(p.elbv2, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	var orphans []cloud.OrphanResource

	for lbPager.HasMorePages() {
		page, err := lbPager.NextPage(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: describe load balancers page: %v\n", err)
			break
		}
		for _, lb := range page.LoadBalancers {
			if lb.LoadBalancerArn == nil {
				continue
			}
			empty, err := p.lbHasNoTargets(ctx, awssdk.ToString(lb.LoadBalancerArn))
			if err != nil || !empty {
				continue
			}
			orphans = append(orphans, cloud.OrphanResource{
				Kind:        cloud.OrphanLoadBalancer,
				ID:          awssdk.ToString(lb.LoadBalancerArn),
				Name:        awssdk.ToString(lb.LoadBalancerName),
				Region:      p.cfg.Region,
				Provider:    "aws",
				MonthlyCost: 16.43, // ~$0.022/hr base ALB charge
				Detail:      fmt.Sprintf("%s has no registered targets", lb.Type),
			})
		}
	}
	return orphans, nil
}

func (p *Provider) lbHasNoTargets(ctx context.Context, lbArn string) (bool, error) {
	out, err := p.elbv2.DescribeTargetGroups(ctx, &elasticloadbalancingv2.DescribeTargetGroupsInput{
		LoadBalancerArn: awssdk.String(lbArn),
	})
	if err != nil {
		return false, fmt.Errorf("describe target groups: %w", err)
	}
	if len(out.TargetGroups) == 0 {
		return true, nil
	}
	for _, tg := range out.TargetGroups {
		health, err := p.elbv2.DescribeTargetHealth(ctx, &elasticloadbalancingv2.DescribeTargetHealthInput{
			TargetGroupArn: tg.TargetGroupArn,
		})
		if err != nil {
			continue
		}
		if len(health.TargetHealthDescriptions) > 0 {
			return false, nil
		}
	}
	return true, nil
}

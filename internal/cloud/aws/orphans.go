package aws

import (
	"context"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/nanohype/cloudgov/internal/cloud"
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
	DescribeSnapshots(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	DescribeImages(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
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

	snaps, err := p.orphanSnapshots(ctx)
	if err != nil {
		return nil, fmt.Errorf("orphan snapshots: %w", err)
	}
	orphans = append(orphans, snaps...)

	images, err := p.orphanImages(ctx)
	if err != nil {
		return nil, fmt.Errorf("orphan images: %w", err)
	}
	orphans = append(orphans, images...)

	// Cluster residue (EKS log groups + Karpenter infra for deleted clusters) is
	// best-effort: it warns and skips on error rather than failing the whole scan.
	orphans = append(orphans, p.orphanClusterResidue(ctx)...)

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
			p.warnf("warn: describe volumes page: %v\n", err)
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
				Detail:      fmt.Sprintf("%d GiB %s, available; est. ~$%.2f/mo (gp2 on-demand list price, not billed actuals)", sizeGB, v.VolumeType, cost),
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
			Detail:      fmt.Sprintf("EIP %s unassociated; est. ~$3.65/mo (~$0.005/hr unassociated rate)", awssdk.ToString(addr.PublicIp)),
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
			p.warnf("warn: describe load balancers page: %v\n", err)
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
				Detail:      fmt.Sprintf("%s has no registered targets; est. ~$16.43/mo base (~$0.022/hr on-demand)", lb.Type),
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

// ebsSnapshotGBMonth is the EBS standard snapshot storage on-demand list price
// (~$0.05/GB-month); used to estimate snapshot/AMI waste.
const ebsSnapshotGBMonth = 0.05

// orphanSnapshots finds self-owned EBS snapshots stranded by AMI deregistration: a
// snapshot AWS created for an AMI (its description is "Created by CreateImage(...) for
// ami-XXXX ...") whose AMI no longer exists and which no current self-owned AMI
// references. Deregistering an AMI does not delete its snapshots, so they linger and
// keep paying for storage. Manual/backup snapshots have no such description, so they
// are never flagged — this keeps false positives low.
func (p *Provider) orphanSnapshots(ctx context.Context) ([]cloud.OrphanResource, error) {
	liveAMIs, amiSnapshots, err := p.selfAMIIndex(ctx)
	if err != nil {
		return nil, err
	}

	pager := ec2.NewDescribeSnapshotsPaginator(p.ec2, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})

	var orphans []cloud.OrphanResource
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			p.warnf("warn: describe snapshots page: %v\n", err)
			break
		}
		for _, s := range page.Snapshots {
			id := awssdk.ToString(s.SnapshotId)
			if amiSnapshots[id] {
				continue // backs a live AMI
			}
			ami := amiIDFromSnapshotDescription(awssdk.ToString(s.Description))
			if ami == "" || liveAMIs[ami] {
				continue // not an AMI-creation snapshot, or its AMI still exists
			}
			sizeGB := awssdk.ToInt32(s.VolumeSize)
			cost := float64(sizeGB) * ebsSnapshotGBMonth
			orphans = append(orphans, cloud.OrphanResource{
				Kind:        cloud.OrphanSnapshot,
				ID:          id,
				Name:        id,
				Region:      p.cfg.Region,
				Provider:    "aws",
				MonthlyCost: cost,
				Detail:      fmt.Sprintf("%d GiB snapshot stranded by deregistered AMI %s; est. ~$%.2f/mo (snapshot storage on-demand list price, not billed actuals)", sizeGB, ami, cost),
			})
		}
	}
	return orphans, nil
}

// selfAMIIndex returns the set of self-owned AMI ids that currently exist and the set
// of snapshot ids those AMIs reference, so a snapshot backing a live AMI is never
// treated as an orphan.
func (p *Provider) selfAMIIndex(ctx context.Context) (liveAMIs, amiSnapshots map[string]bool, err error) {
	out, err := p.ec2.DescribeImages(ctx, &ec2.DescribeImagesInput{Owners: []string{"self"}})
	if err != nil {
		return nil, nil, fmt.Errorf("describe images: %w", err)
	}
	liveAMIs = map[string]bool{}
	amiSnapshots = map[string]bool{}
	for _, img := range out.Images {
		liveAMIs[awssdk.ToString(img.ImageId)] = true
		for _, bdm := range img.BlockDeviceMappings {
			if bdm.Ebs != nil && bdm.Ebs.SnapshotId != nil {
				amiSnapshots[awssdk.ToString(bdm.Ebs.SnapshotId)] = true
			}
		}
	}
	return liveAMIs, amiSnapshots, nil
}

// amiIDFromSnapshotDescription extracts the AMI id from an AWS-generated snapshot
// description ("Created by CreateImage(i-…) for ami-… from vol-… …"), or "" if the
// description isn't an AMI-creation description.
func amiIDFromSnapshotDescription(desc string) string {
	const prefix, marker = "Created by CreateImage", "for "
	if !strings.HasPrefix(desc, prefix) {
		return ""
	}
	i := strings.Index(desc, marker+"ami-")
	if i < 0 {
		return ""
	}
	rest := desc[i+len(marker):] // starts at "ami-…"
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// orphanImages finds self-owned AMIs not referenced by any instance's ImageId. An
// unused AMI keeps paying for its backing snapshots. This is a review signal, not a
// certainty — an AMI deliberately kept for future launches also has no current
// instances — so the Detail says so.
func (p *Provider) orphanImages(ctx context.Context) ([]cloud.OrphanResource, error) {
	out, err := p.ec2.DescribeImages(ctx, &ec2.DescribeImagesInput{Owners: []string{"self"}})
	if err != nil {
		return nil, fmt.Errorf("describe images: %w", err)
	}
	if len(out.Images) == 0 {
		return nil, nil
	}

	inUse, err := p.amisInUseByInstances(ctx)
	if err != nil {
		return nil, err
	}

	var orphans []cloud.OrphanResource
	for _, img := range out.Images {
		id := awssdk.ToString(img.ImageId)
		if inUse[id] {
			continue
		}
		var sizeGB int32
		for _, bdm := range img.BlockDeviceMappings {
			if bdm.Ebs != nil {
				sizeGB += awssdk.ToInt32(bdm.Ebs.VolumeSize)
			}
		}
		cost := float64(sizeGB) * ebsSnapshotGBMonth
		name := awssdk.ToString(img.Name)
		if name == "" {
			name = id
		}
		orphans = append(orphans, cloud.OrphanResource{
			Kind:        cloud.OrphanImage,
			ID:          id,
			Name:        name,
			Region:      p.cfg.Region,
			Provider:    "aws",
			MonthlyCost: cost,
			Detail:      fmt.Sprintf("AMI not referenced by any instance; %d GiB of backing snapshots, est. ~$%.2f/mo (verify before deregistering — AMIs kept for future launches also match)", sizeGB, cost),
		})
	}
	return orphans, nil
}

// amisInUseByInstances returns the set of AMI ids referenced by any instance (in any
// state) in the region.
func (p *Provider) amisInUseByInstances(ctx context.Context) (map[string]bool, error) {
	inUse := map[string]bool{}
	pager := ec2.NewDescribeInstancesPaginator(p.ec2, &ec2.DescribeInstancesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe instances: %w", err)
		}
		for _, r := range page.Reservations {
			for _, inst := range r.Instances {
				if inst.ImageId != nil {
					inUse[awssdk.ToString(inst.ImageId)] = true
				}
			}
		}
	}
	return inUse, nil
}

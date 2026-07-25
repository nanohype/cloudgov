package aws

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// GetRoleInfo fetches an IAM role's ARN, decoded trust policy, tags, attached
// managed-policy ARNs, and inline-policy names — the inputs the platform auditor
// needs to verify tenant-role conformance. Returns (nil, nil) when the role does
// not exist. Half of platform.IdentityReader.
func (p *Provider) GetRoleInfo(ctx context.Context, roleName string) (*cloud.IAMRoleInfo, error) {
	client := p.iam

	out, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: awssdk.String(roleName)})
	if err != nil {
		var notFound *iamtypes.NoSuchEntityException
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("get role %s: %w", roleName, err)
	}

	info := &cloud.IAMRoleInfo{ARN: awssdk.ToString(out.Role.Arn), Tags: map[string]string{}}
	if doc := awssdk.ToString(out.Role.AssumeRolePolicyDocument); doc != "" {
		if dec, derr := url.QueryUnescape(doc); derr == nil {
			info.TrustPolicyDocument = dec
		} else {
			info.TrustPolicyDocument = doc
		}
	}
	for _, t := range out.Role.Tags {
		info.Tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}

	var marker *string
	for {
		la, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: awssdk.String(roleName), Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("list attached policies for %s: %w", roleName, err)
		}
		for _, ap := range la.AttachedPolicies {
			info.AttachedPolicyARNs = append(info.AttachedPolicyARNs, awssdk.ToString(ap.PolicyArn))
		}
		if !la.IsTruncated || la.Marker == nil {
			break
		}
		marker = la.Marker
	}

	marker = nil
	for {
		li, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: awssdk.String(roleName), Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("list inline policies for %s: %w", roleName, err)
		}
		info.InlinePolicyNames = append(info.InlinePolicyNames, li.PolicyNames...)
		if !li.IsTruncated || li.Marker == nil {
			break
		}
		marker = li.Marker
	}
	return info, nil
}

// GetPodIdentityAssociation returns the EKS Pod Identity association binding
// (namespace, serviceAccount) on a cluster, or (nil, nil) when none exists.
// The other half of platform.IdentityReader.
//
// ListPodIdentityAssociations filters server-side on (namespace, serviceAccount)
// but its summaries omit the role ARN, so the one match is resolved through
// DescribePodIdentityAssociation. A (cluster, namespace, serviceAccount) triple
// can hold at most one association, so there is nothing to paginate.
func (p *Provider) GetPodIdentityAssociation(ctx context.Context, clusterName, namespace, serviceAccount string) (*cloud.PodIdentityAssociation, error) {
	list, err := p.eks.ListPodIdentityAssociations(ctx, &eks.ListPodIdentityAssociationsInput{
		ClusterName:    awssdk.String(clusterName),
		Namespace:      awssdk.String(namespace),
		ServiceAccount: awssdk.String(serviceAccount),
	})
	if err != nil {
		var notFound *ekstypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("list pod identity associations for %s/%s on %s: %w", namespace, serviceAccount, clusterName, err)
	}
	if len(list.Associations) == 0 {
		return nil, nil
	}

	summary := list.Associations[0]
	desc, err := p.eks.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{
		ClusterName:   awssdk.String(clusterName),
		AssociationId: summary.AssociationId,
	})
	if err != nil {
		return nil, fmt.Errorf("describe pod identity association %s on %s: %w", awssdk.ToString(summary.AssociationId), clusterName, err)
	}
	if desc == nil || desc.Association == nil {
		return nil, nil
	}
	return &cloud.PodIdentityAssociation{
		ARN:            awssdk.ToString(desc.Association.AssociationArn),
		RoleARN:        awssdk.ToString(desc.Association.RoleArn),
		Namespace:      awssdk.ToString(desc.Association.Namespace),
		ServiceAccount: awssdk.ToString(desc.Association.ServiceAccount),
	}, nil
}

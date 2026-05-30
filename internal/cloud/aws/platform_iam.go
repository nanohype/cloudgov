package aws

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// GetRoleInfo fetches an IAM role's ARN, decoded trust policy, tags, attached
// managed-policy ARNs, and inline-policy names — the inputs the platform auditor
// needs to verify IRSA conformance. Returns (nil, nil) when the role does not
// exist. Satisfies platform.RoleReader.
func (p *Provider) GetRoleInfo(ctx context.Context, roleName string) (*cloud.IAMRoleInfo, error) {
	client := iam.NewFromConfig(p.cfg)

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

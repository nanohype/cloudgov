package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"github.com/nanohype/cloudgov/internal/cloud"
)

// serviceQuotasAPI is the narrow Service Quotas surface used by this package.
type serviceQuotasAPI interface {
	GetServiceQuota(ctx context.Context, params *servicequotas.GetServiceQuotaInput, optFns ...func(*servicequotas.Options)) (*servicequotas.GetServiceQuotaOutput, error)
}

// quotaLimit returns the account's APPLIED limit for (serviceCode, quotaCode),
// falling back to the documented default when Service Quotas has no value or the
// call fails (the quota may be untracked in this region, or access denied). This
// keeps the limit accurate for accounts that raised it, instead of reporting a
// false near-limit against a stale hardcoded default.
func (p *Provider) quotaLimit(ctx context.Context, serviceCode, quotaCode string, fallback float64) float64 {
	if p.servicequotas == nil {
		return fallback
	}
	out, err := p.servicequotas.GetServiceQuota(ctx, &servicequotas.GetServiceQuotaInput{
		ServiceCode: awssdk.String(serviceCode),
		QuotaCode:   awssdk.String(quotaCode),
	})
	if err != nil || out.Quota == nil || out.Quota.Value == nil {
		return fallback
	}
	return *out.Quota.Value
}

// ListQuotas returns service quota utilization for IAM, EC2, S3, Lambda, and RDS.
func (p *Provider) ListQuotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	var quotas []cloud.QuotaUsage

	iamQuotas, err := p.iamQuotas(ctx)
	if err != nil {
		p.warnf("warn: iam quotas: %v\n", err)
	} else {
		quotas = append(quotas, iamQuotas...)
	}

	ec2Quotas, err := p.ec2Quotas(ctx)
	if err != nil {
		p.warnf("warn: ec2 quotas: %v\n", err)
	} else {
		quotas = append(quotas, ec2Quotas...)
	}

	s3Quotas, err := p.s3Quotas(ctx)
	if err != nil {
		p.warnf("warn: s3 quotas: %v\n", err)
	} else {
		quotas = append(quotas, s3Quotas...)
	}

	lambdaQuotas, err := p.lambdaQuotas(ctx)
	if err != nil {
		p.warnf("warn: lambda quotas: %v\n", err)
	} else {
		quotas = append(quotas, lambdaQuotas...)
	}

	rdsQuotas, err := p.rdsQuotas(ctx)
	if err != nil {
		p.warnf("warn: rds quotas: %v\n", err)
	} else {
		quotas = append(quotas, rdsQuotas...)
	}

	// Severity is derived from utilization; set it on the struct so it travels with
	// the finding (JSON output, comparison) rather than being recomputed per reader.
	for i := range quotas {
		quotas[i].Severity = cloud.QuotaSeverity(quotas[i].Utilization)
	}

	return quotas, nil
}

func (p *Provider) iamQuotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	out, err := p.iam.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, fmt.Errorf("get account summary: %w", err)
	}

	sm := out.SummaryMap
	pairs := []struct {
		used, limit string
		name        string
	}{
		{"Users", "UsersQuota", "Users"},
		{"Roles", "RolesQuota", "Roles"},
		{"Groups", "GroupsQuota", "Groups"},
		{"Policies", "PoliciesQuota", "Policies"},
		{"ServerCertificates", "ServerCertificatesQuota", "Server Certificates"},
		{"InstanceProfiles", "InstanceProfilesQuota", "Instance Profiles"},
	}

	var quotas []cloud.QuotaUsage
	for _, pair := range pairs {
		used, hasUsed := sm[pair.used]
		limit, hasLimit := sm[pair.limit]
		if !hasUsed || !hasLimit || limit == 0 {
			continue
		}
		utilization := float64(used) / float64(limit) * 100
		quotas = append(quotas, cloud.QuotaUsage{
			Provider:    "aws",
			Service:     "IAM",
			QuotaName:   pair.name,
			Used:        float64(used),
			Limit:       float64(limit),
			Utilization: utilization,
			Region:      "global",
		})
	}
	return quotas, nil
}

func (p *Provider) ec2Quotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	// EIPs
	addrOut, err := p.ec2.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, fmt.Errorf("describe addresses: %w", err)
	}
	eipUsed := float64(len(addrOut.Addresses))
	eipLimit := p.quotaLimit(ctx, "ec2", "L-0263D0A3", 5)

	// VPCs
	vpcOut, err := p.ec2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe vpcs: %w", err)
	}
	vpcUsed := float64(len(vpcOut.Vpcs))
	vpcLimit := p.quotaLimit(ctx, "vpc", "L-F678F1CE", 5)

	// Security Groups
	var sgCount int
	sgPager := ec2.NewDescribeSecurityGroupsPaginator(p.ec2, &ec2.DescribeSecurityGroupsInput{})
	for sgPager.HasMorePages() {
		page, err := sgPager.NextPage(ctx)
		if err != nil {
			p.warnf("warn: describe security groups page: %v\n", err)
			break
		}
		sgCount += len(page.SecurityGroups)
	}
	sgUsed := float64(sgCount)
	sgLimit := p.quotaLimit(ctx, "vpc", "L-E79EC296", 2500)

	// Internet Gateways
	igwOut, err := p.ec2.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{})
	if err != nil {
		return nil, fmt.Errorf("describe internet gateways: %w", err)
	}
	igwUsed := float64(len(igwOut.InternetGateways))
	igwLimit := p.quotaLimit(ctx, "vpc", "L-A4707A72", 5)

	region := p.cfg.Region
	quotas := []cloud.QuotaUsage{
		{Provider: "aws", Service: "EC2", QuotaName: "Elastic IPs", Used: eipUsed, Limit: eipLimit, Utilization: pct(eipUsed, eipLimit), Region: region},
		{Provider: "aws", Service: "VPC", QuotaName: "VPCs", Used: vpcUsed, Limit: vpcLimit, Utilization: pct(vpcUsed, vpcLimit), Region: region},
		{Provider: "aws", Service: "EC2", QuotaName: "Security Groups", Used: sgUsed, Limit: sgLimit, Utilization: pct(sgUsed, sgLimit), Region: region},
		{Provider: "aws", Service: "VPC", QuotaName: "Internet Gateways", Used: igwUsed, Limit: igwLimit, Utilization: pct(igwUsed, igwLimit), Region: region},
	}
	return quotas, nil
}

func (p *Provider) s3Quotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	out, err := p.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}
	used := float64(len(out.Buckets))
	limit := p.quotaLimit(ctx, "s3", "L-DC2B2D3D", 100)

	return []cloud.QuotaUsage{{
		Provider:    "aws",
		Service:     "S3",
		QuotaName:   "Buckets",
		Used:        used,
		Limit:       limit,
		Utilization: pct(used, limit),
		Region:      "global",
	}}, nil
}

func (p *Provider) lambdaQuotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	settings, err := p.lambda.GetAccountSettings(ctx, &lambda.GetAccountSettingsInput{})
	if err != nil {
		return nil, fmt.Errorf("get account settings: %w", err)
	}

	var quotas []cloud.QuotaUsage

	// Concurrent executions
	if settings.AccountLimit != nil && settings.AccountUsage != nil {
		limit := float64(settings.AccountLimit.ConcurrentExecutions)
		// TotalCodeSize is available; use concurrent executions limit
		if limit > 0 {
			// Count functions
			var fnCount int
			pager := lambda.NewListFunctionsPaginator(p.lambda, &lambda.ListFunctionsInput{})
			for pager.HasMorePages() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					p.warnf("warn: list functions page: %v\n", err)
					break
				}
				fnCount += len(page.Functions)
			}
			quotas = append(quotas, cloud.QuotaUsage{
				Provider:    "aws",
				Service:     "Lambda",
				QuotaName:   "Functions",
				Used:        float64(fnCount),
				Limit:       limit,
				Utilization: pct(float64(fnCount), limit),
				Region:      p.cfg.Region,
			})
		}

		// Code storage
		if settings.AccountLimit.TotalCodeSize > 0 {
			usedBytes := float64(settings.AccountUsage.TotalCodeSize)
			limitBytes := float64(settings.AccountLimit.TotalCodeSize)
			quotas = append(quotas, cloud.QuotaUsage{
				Provider:    "aws",
				Service:     "Lambda",
				QuotaName:   "Code Storage (bytes)",
				Used:        usedBytes,
				Limit:       limitBytes,
				Utilization: pct(usedBytes, limitBytes),
				Region:      p.cfg.Region,
			})
		}
	}

	return quotas, nil
}

func (p *Provider) rdsQuotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	pager := rds.NewDescribeDBInstancesPaginator(p.rds, &rds.DescribeDBInstancesInput{})

	var count int
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe db instances: %w", err)
		}
		count += len(page.DBInstances)
	}

	used := float64(count)
	limit := p.quotaLimit(ctx, "rds", "L-7B6409FD", 40)

	return []cloud.QuotaUsage{{
		Provider:    "aws",
		Service:     "RDS",
		QuotaName:   "DB Instances",
		Used:        used,
		Limit:       limit,
		Utilization: pct(used, limit),
		Region:      p.cfg.Region,
	}}, nil
}

func pct(used, limit float64) float64 {
	if limit == 0 {
		return 0
	}
	return used / limit * 100
}

// compile-time check
var _ cloud.QuotaProvider = (*Provider)(nil)

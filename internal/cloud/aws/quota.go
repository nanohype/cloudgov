package aws

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stxkxs/matlock/internal/cloud"
)

// ListQuotas returns service quota utilization for IAM, EC2, S3, Lambda, and RDS.
func (p *Provider) ListQuotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	var quotas []cloud.QuotaUsage

	iamQuotas, err := p.iamQuotas(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: iam quotas: %v\n", err)
	} else {
		quotas = append(quotas, iamQuotas...)
	}

	ec2Quotas, err := p.ec2Quotas(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: ec2 quotas: %v\n", err)
	} else {
		quotas = append(quotas, ec2Quotas...)
	}

	s3Quotas, err := p.s3Quotas(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: s3 quotas: %v\n", err)
	} else {
		quotas = append(quotas, s3Quotas...)
	}

	lambdaQuotas, err := p.lambdaQuotas(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: lambda quotas: %v\n", err)
	} else {
		quotas = append(quotas, lambdaQuotas...)
	}

	rdsQuotas, err := p.rdsQuotas(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: rds quotas: %v\n", err)
	} else {
		quotas = append(quotas, rdsQuotas...)
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

	// Default EIP limit is 5 per region
	eipLimit := float64(5)

	// VPCs
	vpcOut, err := p.ec2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe vpcs: %w", err)
	}
	vpcUsed := float64(len(vpcOut.Vpcs))
	vpcLimit := float64(5) // Default

	// Security Groups
	var sgCount int
	sgPager := ec2.NewDescribeSecurityGroupsPaginator(p.ec2, &ec2.DescribeSecurityGroupsInput{})
	for sgPager.HasMorePages() {
		page, err := sgPager.NextPage(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: describe security groups page: %v\n", err)
			break
		}
		sgCount += len(page.SecurityGroups)
	}
	sgUsed := float64(sgCount)
	sgLimit := float64(2500) // Default per region

	// Internet Gateways
	igwOut, err := p.ec2.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{})
	if err != nil {
		return nil, fmt.Errorf("describe internet gateways: %w", err)
	}
	igwUsed := float64(len(igwOut.InternetGateways))
	igwLimit := float64(5) // Default per region

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
	limit := float64(100) // Default S3 bucket limit per account

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
					fmt.Fprintf(os.Stderr, "warn: list functions page: %v\n", err)
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
	limit := float64(40) // Default RDS instance limit per region

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

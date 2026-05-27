package aws

import (
	"context"
	"fmt"
	"strconv"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stxkxs/matlock/internal/cloud"
)

// sensitivePortsAWS are ports that should never be open to the internet.
var sensitivePortsAWS = []int{22, 3389, 3306, 5432, 1433, 27017, 6379, 9200}

// AuditNetwork checks all EC2 security groups for overly permissive rules.
func (p *Provider) AuditNetwork(ctx context.Context) ([]cloud.NetworkFinding, error) {
	pager := ec2.NewDescribeSecurityGroupsPaginator(p.ec2, &ec2.DescribeSecurityGroupsInput{})

	var findings []cloud.NetworkFinding
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe security groups: %w", err)
		}
		for _, sg := range page.SecurityGroups {
			findings = append(findings, p.auditSGIngress(sg)...)
			findings = append(findings, p.auditSGEgress(sg)...)
		}
	}
	return findings, nil
}

func (p *Provider) auditSGIngress(sg ec2types.SecurityGroup) []cloud.NetworkFinding {
	var findings []cloud.NetworkFinding
	sgID := awssdk.ToString(sg.GroupId)
	region := p.cfg.Region

	for _, rule := range sg.IpPermissions {
		proto := awssdk.ToString(rule.IpProtocol)

		cidrs := collectOpenCIDRs(rule)
		for _, cidr := range cidrs {
			findings = append(findings, p.classifyIngress(sgID, region, proto, rule, cidr)...)
		}
	}
	return findings
}

func collectOpenCIDRs(rule ec2types.IpPermission) []string {
	var cidrs []string
	for _, r := range rule.IpRanges {
		if cidr := awssdk.ToString(r.CidrIp); cidr == "0.0.0.0/0" {
			cidrs = append(cidrs, cidr)
		}
	}
	for _, r := range rule.Ipv6Ranges {
		if cidr := awssdk.ToString(r.CidrIpv6); cidr == "::/0" {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
}

func (p *Provider) classifyIngress(sgID, region, proto string, rule ec2types.IpPermission, cidr string) []cloud.NetworkFinding {
	fromPort := int(awssdk.ToInt32(rule.FromPort))
	toPort := int(awssdk.ToInt32(rule.ToPort))
	isAllTraffic := proto == "-1"

	// All-traffic rule (protocol -1) is critical
	if isAllTraffic {
		return []cloud.NetworkFinding{{
			Severity:    cloud.SeverityCritical,
			Type:        cloud.NetworkAdminPortOpen,
			Provider:    "aws",
			Resource:    sgID,
			Region:      region,
			Protocol:    "all",
			Port:        "all",
			CIDR:        cidr,
			Detail:      fmt.Sprintf("all traffic allowed from %s", cidr),
			Remediation: fmt.Sprintf("aws ec2 revoke-security-group-ingress --group-id %s --protocol -1 --cidr %s", sgID, cidr),
		}}
	}

	// Check sensitive ports
	for _, sp := range sensitivePortsAWS {
		if portInRange(sp, fromPort, toPort) {
			return []cloud.NetworkFinding{{
				Severity:    cloud.SeverityCritical,
				Type:        cloud.NetworkAdminPortOpen,
				Provider:    "aws",
				Resource:    sgID,
				Region:      region,
				Protocol:    proto,
				Port:        strconv.Itoa(sp),
				CIDR:        cidr,
				Detail:      fmt.Sprintf("sensitive port %d open to internet via %s", sp, cidr),
				Remediation: fmt.Sprintf("aws ec2 revoke-security-group-ingress --group-id %s --protocol %s --port %d --cidr %s", sgID, proto, sp, cidr),
			}}
		}
	}

	// HTTP/HTTPS is expected to be open
	if proto == "tcp" && fromPort == toPort && (fromPort == 80 || fromPort == 443) {
		return nil
	}

	portStr := portStr(fromPort, toPort)
	return []cloud.NetworkFinding{{
		Severity:    cloud.SeverityHigh,
		Type:        cloud.NetworkOpenIngress,
		Provider:    "aws",
		Resource:    sgID,
		Region:      region,
		Protocol:    proto,
		Port:        portStr,
		CIDR:        cidr,
		Detail:      fmt.Sprintf("unrestricted ingress on %s port(s) %s from %s", proto, portStr, cidr),
		Remediation: fmt.Sprintf("aws ec2 revoke-security-group-ingress --group-id %s --protocol %s --port %s --cidr %s", sgID, proto, portStr, cidr),
	}}
}

func (p *Provider) auditSGEgress(sg ec2types.SecurityGroup) []cloud.NetworkFinding {
	var findings []cloud.NetworkFinding
	sgID := awssdk.ToString(sg.GroupId)
	region := p.cfg.Region

	for _, rule := range sg.IpPermissionsEgress {
		proto := awssdk.ToString(rule.IpProtocol)
		if proto != "-1" {
			continue // only flag unrestricted all-traffic egress
		}
		for _, r := range rule.IpRanges {
			if awssdk.ToString(r.CidrIp) == "0.0.0.0/0" {
				findings = append(findings, cloud.NetworkFinding{
					Severity:    cloud.SeverityMedium,
					Type:        cloud.NetworkOpenEgress,
					Provider:    "aws",
					Resource:    sgID,
					Region:      region,
					Protocol:    "all",
					Port:        "all",
					CIDR:        "0.0.0.0/0",
					Detail:      "unrestricted egress to all destinations",
					Remediation: fmt.Sprintf("aws ec2 revoke-security-group-egress --group-id %s --protocol -1 --cidr 0.0.0.0/0", sgID),
				})
				break
			}
		}
	}
	return findings
}

func portInRange(port, from, to int) bool {
	if from == 0 && to == 0 {
		return false
	}
	return port >= from && port <= to
}

func portStr(from, to int) string {
	if from == to {
		return strconv.Itoa(from)
	}
	return fmt.Sprintf("%d-%d", from, to)
}

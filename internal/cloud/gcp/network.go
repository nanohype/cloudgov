package gcp

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/api/compute/v1"

	"github.com/stxkxs/matlock/internal/cloud"
)

// AuditNetwork checks GCP firewall rules for overly permissive ingress/egress.
func (p *Provider) AuditNetwork(ctx context.Context) ([]cloud.NetworkFinding, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GCP project ID is required")
	}
	fws, err := p.compute.ListFirewalls(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("list firewalls: %w", err)
	}
	var findings []cloud.NetworkFinding
	for _, fw := range fws {
		findings = append(findings, classifyFirewall(fw)...)
	}
	return findings, nil
}

// gcpSensitivePorts are port numbers that should never be exposed to the internet.
var gcpSensitivePorts = []int{22, 3389, 3306, 5432, 1433, 27017, 6379, 9200}

func classifyFirewall(fw *compute.Firewall) []cloud.NetworkFinding {
	var findings []cloud.NetworkFinding
	if fw.Disabled {
		return nil
	}

	isIngress := fw.Direction == "" || strings.EqualFold(fw.Direction, "INGRESS")
	isEgress := strings.EqualFold(fw.Direction, "EGRESS")

	openToInternet := false
	for _, src := range fw.SourceRanges {
		if src == "0.0.0.0/0" || src == "::/0" {
			openToInternet = true
			break
		}
	}
	destToInternet := false
	for _, dst := range fw.DestinationRanges {
		if dst == "0.0.0.0/0" || dst == "::/0" {
			destToInternet = true
			break
		}
	}

	if isIngress && openToInternet {
		for _, allowed := range fw.Allowed {
			findings = append(findings, classifyFirewallAllowed(fw.Name, allowed)...)
		}
	}

	if isEgress && destToInternet {
		for _, allowed := range fw.Allowed {
			if allowed.IPProtocol == "all" {
				findings = append(findings, cloud.NetworkFinding{
					Severity:    cloud.SeverityMedium,
					Type:        cloud.NetworkOpenEgress,
					Provider:    "gcp",
					Resource:    fw.Name,
					Protocol:    "all",
					Port:        "all",
					CIDR:        "0.0.0.0/0",
					Detail:      fmt.Sprintf("firewall rule %s allows all egress to internet", fw.Name),
					Remediation: fmt.Sprintf("gcloud compute firewall-rules delete %s", fw.Name),
				})
				break
			}
		}
	}

	return findings
}

func classifyFirewallAllowed(fwName string, allowed *compute.FirewallAllowed) []cloud.NetworkFinding {
	var findings []cloud.NetworkFinding
	proto := allowed.IPProtocol

	if proto == "all" {
		return []cloud.NetworkFinding{{
			Severity:    cloud.SeverityCritical,
			Type:        cloud.NetworkAdminPortOpen,
			Provider:    "gcp",
			Resource:    fwName,
			Protocol:    "all",
			Port:        "all",
			CIDR:        "0.0.0.0/0",
			Detail:      fmt.Sprintf("firewall rule %s allows all ingress from internet", fwName),
			Remediation: fmt.Sprintf("gcloud compute firewall-rules delete %s", fwName),
		}}
	}

	for _, portRange := range allowed.Ports {
		from, to := parsePortRange(portRange)
		for _, sp := range gcpSensitivePorts {
			if sp >= from && sp <= to {
				return []cloud.NetworkFinding{{
					Severity:    cloud.SeverityCritical,
					Type:        cloud.NetworkAdminPortOpen,
					Provider:    "gcp",
					Resource:    fwName,
					Protocol:    proto,
					Port:        strconv.Itoa(sp),
					CIDR:        "0.0.0.0/0",
					Detail:      fmt.Sprintf("firewall rule %s exposes sensitive port %d to internet", fwName, sp),
					Remediation: fmt.Sprintf("gcloud compute firewall-rules delete %s", fwName),
				}}
			}
		}

		// Skip HTTP/HTTPS
		if proto == "tcp" && (portRange == "80" || portRange == "443") {
			continue
		}

		findings = append(findings, cloud.NetworkFinding{
			Severity:    cloud.SeverityHigh,
			Type:        cloud.NetworkOpenIngress,
			Provider:    "gcp",
			Resource:    fwName,
			Protocol:    proto,
			Port:        portRange,
			CIDR:        "0.0.0.0/0",
			Detail:      fmt.Sprintf("firewall rule %s allows %s/%s ingress from internet", fwName, proto, portRange),
			Remediation: fmt.Sprintf("gcloud compute firewall-rules delete %s", fwName),
		})
	}

	// Rule with no specific ports means all ports for that protocol
	if len(allowed.Ports) == 0 && proto != "all" {
		findings = append(findings, cloud.NetworkFinding{
			Severity:    cloud.SeverityHigh,
			Type:        cloud.NetworkOpenIngress,
			Provider:    "gcp",
			Resource:    fwName,
			Protocol:    proto,
			Port:        "all",
			CIDR:        "0.0.0.0/0",
			Detail:      fmt.Sprintf("firewall rule %s allows all %s ingress from internet", fwName, proto),
			Remediation: fmt.Sprintf("gcloud compute firewall-rules delete %s", fwName),
		})
	}

	return findings
}

func parsePortRange(portRange string) (int, int) {
	parts := strings.SplitN(portRange, "-", 2)
	from, _ := strconv.Atoi(parts[0])
	if len(parts) == 1 {
		return from, from
	}
	to, _ := strconv.Atoi(parts[1])
	return from, to
}

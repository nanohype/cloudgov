package cloud

import "context"

// NetworkFindingType classifies a network security finding.
type NetworkFindingType string

const (
	NetworkOpenIngress   NetworkFindingType = "OPEN_INGRESS"    // non-80/443 port open to internet
	NetworkOpenEgress    NetworkFindingType = "OPEN_EGRESS"     // unrestricted egress
	NetworkAdminPortOpen NetworkFindingType = "ADMIN_PORT_OPEN" // SSH/RDP/DB port to internet
	NetworkWideCIDR      NetworkFindingType = "WIDE_CIDR"       // wide CIDR on sensitive port
)

// NetworkFinding is a single network security observation.
type NetworkFinding struct {
	Severity    Severity
	Type        NetworkFindingType
	Provider    string
	Resource    string // sg-id / firewall-name / NSG name
	Region      string
	Protocol    string
	Port        string
	CIDR        string
	Detail      string
	Remediation string
}

// NetworkProvider audits network security groups and firewall rules.
type NetworkProvider interface {
	Provider
	AuditNetwork(ctx context.Context) ([]NetworkFinding, error)
}

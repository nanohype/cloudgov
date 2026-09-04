package cloud

import "context"

// OrphanKind classifies the type of orphaned resource.
type OrphanKind string

const (
	OrphanDisk         OrphanKind = "disk"
	OrphanIP           OrphanKind = "ip"
	OrphanLoadBalancer OrphanKind = "load_balancer"
	OrphanSnapshot     OrphanKind = "snapshot"
	OrphanImage        OrphanKind = "image"

	// Manual RDS snapshots outlive the database they were taken from: deleting an
	// instance or cluster removes its automated backups but never its manual
	// snapshots, so a torn-down stack leaves billable storage behind with nothing
	// left to point at it. CDK/CloudFormation's RemovalPolicy.SNAPSHOT produces
	// exactly this on every destroy.
	OrphanDBSnapshot        OrphanKind = "db_snapshot"
	OrphanDBClusterSnapshot OrphanKind = "db_cluster_snapshot"

	// Cluster residue: resources tied to a now-deleted EKS cluster that the
	// cluster's IaC teardown can't reach, so they linger. The log group blocks a
	// same-named re-vend; the Karpenter infra is stale cruft.
	OrphanEKSLogGroup    OrphanKind = "eks_log_group"
	OrphanKarpenterQueue OrphanKind = "karpenter_queue"
	OrphanKarpenterRule  OrphanKind = "karpenter_rule"
)

// AllOrphanKinds is every kind this scanner can emit.
//
// SARIF declares one rule per kind and takes the ruleId straight from the kind,
// so a kind with no rule produces a result referencing a rule that is not
// declared in the run — invalid SARIF that most consumers drop silently. The
// rule table is built from this list rather than from a second one written
// beside it, and TestEveryFindingTypeListHoldsEveryConstantOfItsType holds this
// list against the constants above.
var AllOrphanKinds = []OrphanKind{
	OrphanDisk,
	OrphanIP,
	OrphanLoadBalancer,
	OrphanSnapshot,
	OrphanImage,
	OrphanDBSnapshot,
	OrphanDBClusterSnapshot,
	OrphanEKSLogGroup,
	OrphanKarpenterQueue,
	OrphanKarpenterRule,
}

// AlwaysReport reports whether this kind must be surfaced regardless of the
// --min-cost threshold. Cluster residue is a correctness/conflict problem (a
// stale resource that blocks re-creation), not cost waste, so its ~$0 estimate
// must not let a cost filter hide it.
func (k OrphanKind) AlwaysReport() bool {
	switch k {
	case OrphanEKSLogGroup, OrphanKarpenterQueue, OrphanKarpenterRule:
		return true
	default:
		return false
	}
}

// OrphanResource is an unused cloud resource that is accruing cost.
type OrphanResource struct {
	Kind        OrphanKind
	ID          string
	Name        string
	Region      string
	Provider    string
	MonthlyCost float64 // estimated; 0 if unknown
	Detail      string
}

// OrphansProvider lists unused resources.
type OrphansProvider interface {
	Provider
	ListOrphans(ctx context.Context) ([]OrphanResource, error)
}

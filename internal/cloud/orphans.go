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
)

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

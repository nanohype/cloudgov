package cloud

import (
	"context"
	"time"
)

// IAMProvider fetches IAM data and computes minimal policies.
type IAMProvider interface {
	Provider
	ListPrincipals(ctx context.Context) ([]Principal, error)
	GrantedPermissions(ctx context.Context, p Principal) ([]Permission, error)
	UsedPermissions(ctx context.Context, p Principal, since time.Time) ([]Permission, error)
	MinimalPolicy(ctx context.Context, p Principal, used []Permission) (Policy, error)
}

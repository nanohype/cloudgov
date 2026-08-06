package iam

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nanohype/cloudgov/internal/cloud"
	"golang.org/x/sync/errgroup"
)

// ScanOptions controls how the analyzer behaves.
type ScanOptions struct {
	Days            int
	PrincipalFilter string // empty = all
	MinSeverity     cloud.Severity
	Concurrency     int // max parallel goroutines; 0 or negative defaults to 10
	// Progress is called after each principal is attempted; nil = no-op. It is
	// invoked from the scan's worker goroutines, so an implementation that
	// touches shared state must synchronize. total is the number of principals
	// attempted, which is not Result.Scanned — that counts the ones actually
	// analyzed, and is lower whenever a principal could not be read.
	Progress func(done, total int)
}

// Result is the output of an IAM scan.
type Result struct {
	Findings   []cloud.Finding
	Principals int
	// Scanned counts principals actually analyzed — one whose permissions
	// could not be read is not one of them. Counting attempts instead would
	// report full coverage for a scan that read nothing.
	Scanned         int
	UsedPermissions map[string][]cloud.Permission
	// Incomplete lists the principals that could not be analyzed and why. A
	// non-empty value means Findings is a partial view: the permissions of
	// those principals were never compared against anything.
	Incomplete []string
}

// Scan runs the full IAM scan against a provider: fetch principals, compare
// granted vs used permissions, and emit findings.
func Scan(ctx context.Context, provider cloud.IAMProvider, opts ScanOptions) (Result, error) {
	since := time.Now().AddDate(0, 0, -opts.Days)

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	principals, err := provider.ListPrincipals(ctx)
	if err != nil {
		return Result{}, err
	}

	// Pre-filter to know the total before launching goroutines (needed for progress reporting).
	var toScan []cloud.Principal
	for _, p := range principals {
		if opts.PrincipalFilter != "" &&
			p.Name != opts.PrincipalFilter &&
			p.ID != opts.PrincipalFilter {
			continue
		}
		toScan = append(toScan, p)
	}

	var result Result
	result.Principals = len(principals)
	result.UsedPermissions = make(map[string][]cloud.Permission)

	// total drives progress reporting (how many were attempted); result.Scanned
	// counts how many were actually analyzed, and is set once the group is done.
	total := len(toScan)
	var scanned atomic.Int64

	var mu sync.Mutex
	var doneCount atomic.Int64
	sem := make(chan struct{}, concurrency)
	g, gctx := errgroup.WithContext(ctx)

	for _, p := range toScan {
		p := p // capture loop variable
		sem <- struct{}{}
		g.Go(func() error {
			defer func() {
				<-sem
				n := int(doneCount.Add(1))
				if opts.Progress != nil {
					opts.Progress(n, total)
				}
			}()

			// A principal whose permissions cannot be read is not analyzed:
			// it contributes no findings, and every finding this scanner
			// produces is a comparison of granted against used. Silently
			// returning nil here made a denied or throttled principal
			// indistinguishable from a clean one.
			granted, err := provider.GrantedPermissions(gctx, p)
			if err != nil {
				mu.Lock()
				result.Incomplete = append(result.Incomplete,
					fmt.Sprintf("principal %s: granted permissions: %v", p.Name, err))
				mu.Unlock()
				return nil
			}

			used, err := provider.UsedPermissions(gctx, p, since)
			if err != nil {
				// Worse than a missing finding: analyze() reads an empty used-set
				// as "never used", so proceeding would invent a stale-principal
				// finding and mark every granted permission unused.
				mu.Lock()
				result.Incomplete = append(result.Incomplete,
					fmt.Sprintf("principal %s: used permissions: %v", p.Name, err))
				mu.Unlock()
				return nil
			}
			scanned.Add(1)

			if len(used) > 0 {
				mu.Lock()
				result.UsedPermissions[p.ID] = used
				mu.Unlock()
			}

			findings := analyze(p, granted, used, opts.Days)
			var toAdd []cloud.Finding
			for _, f := range findings {
				if cloud.SeverityRank(f.Severity) >= cloud.SeverityRank(opts.MinSeverity) {
					toAdd = append(toAdd, f)
				}
			}

			if len(toAdd) > 0 {
				mu.Lock()
				result.Findings = append(result.Findings, toAdd...)
				mu.Unlock()
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return Result{}, err
	}
	result.Scanned = int(scanned.Load())
	sort.Strings(result.Incomplete)

	// Sort by severity desc, then principal name
	sort.Slice(result.Findings, func(i, j int) bool {
		ri := cloud.SeverityRank(result.Findings[i].Severity)
		rj := cloud.SeverityRank(result.Findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		ni, nj := "", ""
		if result.Findings[i].Principal != nil {
			ni = result.Findings[i].Principal.Name
		}
		if result.Findings[j].Principal != nil {
			nj = result.Findings[j].Principal.Name
		}
		return ni < nj
	})

	return result, nil
}

// analyze computes the delta between granted and used permissions for one principal.
func analyze(p cloud.Principal, granted, used []cloud.Permission, days int) []cloud.Finding {
	var findings []cloud.Finding

	// Index used permissions for fast lookup
	usedSet := make(map[string]bool)
	for _, u := range used {
		usedSet[normalizeKey(u.Action, u.Resource)] = true
		// Also match wildcard resources
		usedSet[normalizeKey(u.Action, "*")] = true
	}

	accountID := ""
	if p.Metadata != nil {
		accountID = p.Metadata["account_id"]
	}

	for _, g := range granted {
		// Critical: admin / wildcard action
		if isAdminAction(g.Action) {
			findings = append(findings, cloud.Finding{
				Severity:    cloud.SeverityCritical,
				Type:        cloud.FindingAdminAccess,
				Provider:    p.Provider,
				Principal:   &p,
				Resource:    g.Resource,
				Detail:      "principal has admin-level permission: " + g.Action,
				Remediation: "Remove or scope this permission to specific resources and actions.",
			})
			continue
		}

		// Critical: wildcard resource
		if isWildcardResource(g.Resource) && !isAdminAction(g.Action) {
			findings = append(findings, cloud.Finding{
				Severity:    cloud.SeverityCritical,
				Type:        cloud.FindingWildcardResource,
				Provider:    p.Provider,
				Principal:   &p,
				Resource:    g.Resource,
				Detail:      g.Action + " granted on wildcard resource " + g.Resource,
				Remediation: "Scope the resource to a specific ARN / path instead of *.",
			})
		}

		// High: cross-account access (AWS-specific)
		if accountID != "" && isCrossAccount(accountID, g.Resource) {
			findings = append(findings, cloud.Finding{
				Severity:    cloud.SeverityHigh,
				Type:        cloud.FindingCrossAccountAccess,
				Provider:    p.Provider,
				Principal:   &p,
				Resource:    g.Resource,
				Detail:      "permission grants access to a resource in another account",
				Remediation: "Verify this cross-account trust is intentional and document it.",
			})
		}

		// High: granted but never used
		key := normalizeKey(g.Action, g.Resource)
		keyWild := normalizeKey(g.Action, "*")
		if !usedSet[key] && !usedSet[keyWild] && len(used) > 0 {
			findings = append(findings, cloud.Finding{
				Severity:    cloud.SeverityHigh,
				Type:        cloud.FindingUnusedPermission,
				Provider:    p.Provider,
				Principal:   &p,
				Resource:    g.Resource,
				Detail:      g.Action + " was not used in the last " + itoa(days) + " days",
				Remediation: "Remove " + g.Action + " from the policy if it is no longer needed.",
			})
		}
	}

	// Medium: stale principal — zero activity in audit logs
	if len(used) == 0 && len(granted) > 0 {
		findings = append(findings, cloud.Finding{
			Severity:    cloud.SeverityMedium,
			Type:        cloud.FindingStalePrincipal,
			Provider:    p.Provider,
			Principal:   &p,
			Detail:      "no activity detected in the last " + itoa(days) + " days",
			Remediation: "Consider disabling or deleting this principal if it is no longer in use.",
		})
	}

	return dedupFindings(findings)
}

func normalizeKey(action, resource string) string {
	return strings.ToLower(action) + "|" + resource
}

func isAdminAction(action string) bool {
	return action == "*" || strings.HasSuffix(action, ":*") ||
		action == "iam:*"
}

func isWildcardResource(resource string) bool {
	return resource == "*"
}

func isCrossAccount(accountID, resource string) bool {
	if !strings.HasPrefix(resource, "arn:aws:") {
		return false
	}
	parts := strings.Split(resource, ":")
	if len(parts) < 5 {
		return false
	}
	return parts[4] != "" && parts[4] != "*" && parts[4] != accountID
}

func dedupFindings(findings []cloud.Finding) []cloud.Finding {
	type key struct {
		t   cloud.FindingType
		r   string
		pid string
	}
	seen := make(map[key]bool)
	var out []cloud.Finding
	for _, f := range findings {
		pid := ""
		if f.Principal != nil {
			pid = f.Principal.ID
		}
		k := key{f.Type, f.Resource, pid}
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

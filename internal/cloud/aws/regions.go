package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// Region fan-out.
//
// Every regional AWS API answers only for the region its client is bound to, so
// a provider built from a single config sees a single region. Nothing in the
// resulting report says so: the rows carry a Region column, the command is named
// for the account, and a scan that read one region is indistinguishable from one
// that read them all. An empty result then reads as "the account is clean" when
// it means "the configured region is clean".
//
// So a regional scan runs once per region and each finding is stamped with the
// region it was actually read from. Global services — IAM, Cost Explorer, the S3
// bucket list — are scanned once; fanning them out would multiply one finding by
// the region count.
//
// Which regions: every region enabled for the account, unless --regions narrows
// it. Enumeration failure is not silently narrowed to the configured region —
// it goes through warnf, so the run reports as incomplete rather than clean.

// regionFanout bounds concurrent per-region scans. AWS applies per-region
// request quotas, so the ceiling is about the account-wide burst a full sweep
// creates across ~17 enabled regions, not about any single region's limit.
const regionFanout = 8

// root returns the provider that owns the shared warning and region state.
// Region-bound providers from forRegion carry a parent pointer; the root's
// parent is nil. Sharing through a pointer rather than copying the struct keeps
// the mutex uncopied and lets a sub-provider's warnings surface in Incomplete.
func (p *Provider) root() *Provider {
	for p.parent != nil {
		p = p.parent
	}
	return p
}

// regionsToScan returns the regions a regional scan covers, resolved once per
// provider tree and memoised.
func (p *Provider) regionsToScan(ctx context.Context) []string {
	r := p.root()
	r.regionsOnce.Do(func() { r.resolvedRegions = r.discoverRegions(ctx) })
	return r.resolvedRegions
}

// discoverRegions resolves the region set: an explicit --regions list if given,
// otherwise every region enabled for this account.
//
// DescribeRegions without AllRegions returns only enabled regions, which is the
// set that can hold billable resources — a disabled region cannot, and scanning
// it would spend a request per domain to prove it.
func (p *Provider) discoverRegions(ctx context.Context) []string {
	if len(p.regions) > 0 {
		return normalizeRegions(p.regions)
	}
	if p.ec2 == nil {
		return p.configuredRegionOnly()
	}
	out, err := p.ec2.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		p.warnf("warn: describe regions: %v; scanned %s only\n", err, p.cfg.Region)
		return p.configuredRegionOnly()
	}
	var names []string
	for _, r := range out.Regions {
		if r.RegionName != nil && *r.RegionName != "" {
			names = append(names, *r.RegionName)
		}
	}
	if len(names) == 0 {
		p.warnf("warn: describe regions returned none; scanned %s only\n", p.cfg.Region)
		return p.configuredRegionOnly()
	}
	return normalizeRegions(names)
}

// configuredRegionOnly is the fallback when the region set cannot be discovered.
// It is only ever reached from a warnf call site, so the narrowed scope is
// recorded as an incomplete observation rather than passing for a full sweep.
func (p *Provider) configuredRegionOnly() []string {
	if p.cfg.Region == "" {
		return nil
	}
	return []string{p.cfg.Region}
}

// normalizeRegions de-duplicates and sorts, so a scan's output order does not
// depend on the order AWS happened to list regions in.
func normalizeRegions(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// forRegion returns a provider whose regional clients are bound to region.
//
// Tests construct Provider directly with mocks and leave clientsForRegion nil;
// that yields the receiver unchanged, so a mock-backed provider scans exactly
// once and existing tests describe the same single-region behaviour they always
// did. Multi-region tests set clientsForRegion explicitly.
func (p *Provider) forRegion(region string) *Provider {
	if p.clientsForRegion == nil {
		return p
	}
	return p.clientsForRegion(region)
}

// eachRegion runs scan once per region in the account's region set and returns
// the concatenated findings in region order.
//
// A region that fails is warned and skipped rather than sinking the sweep — one
// region denying a call should not discard what the other sixteen found. The
// warning makes the run incomplete, so the partial result cannot be read as a
// clean account. If every region fails there is nothing to report and no basis
// for calling the account clean, so the first error is returned.
func eachRegion[T any](ctx context.Context, p *Provider, scan func(context.Context, *Provider) ([]T, error)) ([]T, error) {
	// A provider that cannot bind clients per region has exactly one region's
	// worth of clients, whatever DescribeRegions says. Fanning out would rescan
	// the same clients and report every finding once per region.
	if p.clientsForRegion == nil {
		return scan(ctx, p)
	}
	regions := p.regionsToScan(ctx)
	if len(regions) == 0 {
		return scan(ctx, p)
	}
	if len(regions) == 1 {
		// One region still binds a client to it. Scanning with the receiver
		// would read whichever region the credentials were configured for and
		// report the answer under the requested region's name — so
		// `--regions eu-west-1` from a us-west-2 profile would return us-west-2's
		// resources, or an empty result that reads as an empty region.
		return scan(ctx, p.forRegion(regions[0]))
	}

	type result struct {
		out []T
		err error
	}
	results := make([]result, len(regions))

	var wg sync.WaitGroup
	sem := make(chan struct{}, regionFanout)
	for i, region := range regions {
		wg.Add(1)
		go func(i int, region string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out, err := scan(ctx, p.forRegion(region))
			results[i] = result{out: out, err: err}
		}(i, region)
	}
	wg.Wait()

	var (
		all      []T
		firstErr error
		failed   int
	)
	for i, r := range results {
		if r.err != nil {
			failed++
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", regions[i], r.err)
			}
			p.warnf("warn: %s: %v\n", regions[i], r.err)
			continue
		}
		all = append(all, r.out...)
	}
	if failed == len(regions) {
		return nil, firstErr
	}
	return all, nil
}

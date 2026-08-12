package aws

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

// fanOutProvider builds a root provider that discovers the given regions and
// can bind clients per region. Each region-bound child records the region it was
// built for, so a test can assert which regions were actually scanned rather
// than trusting that the fan-out ran.
func fanOutProvider(warn *bytes.Buffer, regions ...string) *Provider {
	root := &Provider{
		cfg:   awssdk.Config{Region: "us-west-2"},
		ec2:   &mockEC2{regionsOut: regions},
		warnw: warn,
	}
	root.clientsForRegion = func(region string) *Provider {
		return &Provider{cfg: awssdk.Config{Region: region}, parent: root}
	}
	return root
}

// collectRegions returns the region each scan call saw, in result order.
func collectRegions(t *testing.T, p *Provider) []string {
	t.Helper()
	got, err := eachRegion(context.Background(), p, func(_ context.Context, rp *Provider) ([]string, error) {
		return []string{rp.cfg.Region}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return got
}

func TestEachRegion_ScansEveryRegionInOrder(t *testing.T) {
	var warn bytes.Buffer
	p := fanOutProvider(&warn, "us-east-1", "eu-west-1", "ap-south-1")

	got := collectRegions(t, p)

	want := []string{"ap-south-1", "eu-west-1", "us-east-1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("scanned %v, want %v (sorted, so output order does not depend on the order AWS listed them)", got, want)
	}
}

// A provider built with mocks and no region-bound client factory holds exactly
// one region's worth of clients. Fanning it out would rescan the same clients
// and report every finding once per region — an inflated result that still
// reads as a clean multi-region sweep.
func TestEachRegion_WithoutClientFactoryScansOnce(t *testing.T) {
	p := &Provider{
		cfg: awssdk.Config{Region: "us-west-2"},
		ec2: &mockEC2{regionsOut: []string{"us-east-1", "eu-west-1", "ap-south-1"}},
	}

	var calls int
	got, err := eachRegion(context.Background(), p, func(_ context.Context, rp *Provider) ([]string, error) {
		calls++
		return []string{rp.cfg.Region}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("scanned %d times against one set of clients, want 1 — findings would be duplicated per region", calls)
	}
	if len(got) != 1 || got[0] != "us-west-2" {
		t.Errorf("got %v, want [us-west-2]", got)
	}
}

// One region denying a call must not discard what the others found, and must not
// let the partial result pass for a whole-account sweep.
func TestEachRegion_FailedRegionIsSkippedAndRecorded(t *testing.T) {
	var warn bytes.Buffer
	p := fanOutProvider(&warn, "us-east-1", "eu-west-1", "ap-south-1")

	got, err := eachRegion(context.Background(), p, func(_ context.Context, rp *Provider) ([]string, error) {
		if rp.cfg.Region == "eu-west-1" {
			return nil, errors.New("access denied")
		}
		return []string{rp.cfg.Region}, nil
	})
	if err != nil {
		t.Fatalf("one failing region sank the whole sweep: %v", err)
	}

	want := []string{"ap-south-1", "us-east-1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
	if inc := p.Incomplete(); len(inc) != 1 || !strings.Contains(inc[0], "eu-west-1") {
		t.Errorf("Incomplete() = %v, want the unread region recorded so the result cannot read as clean", inc)
	}
}

func TestEachRegion_AllRegionsFailingReturnsError(t *testing.T) {
	var warn bytes.Buffer
	p := fanOutProvider(&warn, "us-east-1", "eu-west-1")

	got, err := eachRegion(context.Background(), p, func(_ context.Context, _ *Provider) ([]string, error) {
		return nil, errors.New("access denied")
	})
	if err == nil {
		t.Fatal("every region failed and the scan returned no error — an empty result would read as an empty account")
	}
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestRegionsToScan_ExplicitListWins(t *testing.T) {
	var warn bytes.Buffer
	p := fanOutProvider(&warn, "us-east-1", "eu-west-1", "ap-south-1")
	p.regions = []string{"eu-central-1", "us-west-1"}

	got := p.regionsToScan(context.Background())

	if strings.Join(got, ",") != "eu-central-1,us-west-1" {
		t.Errorf("got %v, want the --regions list, not the discovered set", got)
	}
}

// Falling back to the configured region is a narrowing of scope, so it has to be
// recorded — otherwise a discovery failure silently turns an account sweep into
// a one-region scan that still reports as complete.
func TestRegionsToScan_DiscoveryFailureNarrowsAndRecords(t *testing.T) {
	var warn bytes.Buffer
	p := fanOutProvider(&warn)
	p.ec2 = &mockEC2{regionsErr: errors.New("STS expired")}

	got := p.regionsToScan(context.Background())

	if strings.Join(got, ",") != "us-west-2" {
		t.Errorf("got %v, want [us-west-2]", got)
	}
	if inc := p.Incomplete(); len(inc) != 1 || !strings.Contains(inc[0], "describe regions") {
		t.Errorf("Incomplete() = %v, want the narrowed scope recorded", inc)
	}
}

func TestRegionsToScan_EmptyDiscoveryNarrowsAndRecords(t *testing.T) {
	var warn bytes.Buffer
	p := fanOutProvider(&warn)

	got := p.regionsToScan(context.Background())

	if strings.Join(got, ",") != "us-west-2" {
		t.Errorf("got %v, want [us-west-2]", got)
	}
	if inc := p.Incomplete(); len(inc) != 1 {
		t.Errorf("Incomplete() = %v, want the narrowed scope recorded", inc)
	}
}

// Region discovery is one API call per run, not one per domain: a full audit
// resolves the set once and every scanner reuses it.
func TestRegionsToScan_ResolvedOnce(t *testing.T) {
	var warn bytes.Buffer
	m := &mockEC2{regionsOut: []string{"us-east-1", "eu-west-1"}}
	p := fanOutProvider(&warn)
	p.ec2 = m

	for range 5 {
		p.regionsToScan(context.Background())
	}

	if m.regionsCalls != 1 {
		t.Errorf("DescribeRegions called %d times, want 1", m.regionsCalls)
	}
}

// A warning raised inside a region-bound child has to reach the root, or a
// region the sweep could not read is lost with the sub-provider that hit it.
func TestWarnfFromRegionalChildReachesRoot(t *testing.T) {
	var warn bytes.Buffer
	root := fanOutProvider(&warn, "us-east-1")
	child := root.forRegion("us-east-1")

	child.warnf("warn: %s: unreadable\n", "us-east-1")

	if inc := root.Incomplete(); len(inc) != 1 || !strings.Contains(inc[0], "us-east-1") {
		t.Errorf("root Incomplete() = %v, want the child's warning", inc)
	}
	if !strings.Contains(warn.String(), "us-east-1") {
		t.Errorf("child warning did not reach the root's writer: %q", warn.String())
	}
}

func TestEachRegion_ConcurrentWarningsAreSerialized(t *testing.T) {
	var warn bytes.Buffer
	p := fanOutProvider(&warn, "a", "b", "c", "d", "e", "f", "g", "h", "i", "j")

	_, err := eachRegion(context.Background(), p, func(_ context.Context, rp *Provider) ([]string, error) {
		return nil, errors.New("denied")
	})
	if err == nil {
		t.Fatal("expected an error when every region fails")
	}
	if got := len(p.Incomplete()); got != 10 {
		t.Errorf("recorded %d warnings, want 10", got)
	}
}

func TestNormalizeRegions(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"sorts", []string{"us-west-2", "ap-south-1"}, "ap-south-1,us-west-2"},
		{"dedupes", []string{"us-east-1", "us-east-1"}, "us-east-1"},
		{"drops blanks", []string{"us-east-1", "", "  "}, "us-east-1"},
		{"trims", []string{" us-east-1 "}, "us-east-1"},
		{"empty", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strings.Join(normalizeRegions(tt.in), ","); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// The fan-out writes each region's result into its own slot, so the race
// detector has something to prove on `go test -race`.
func TestEachRegion_ResultsAreIndependentPerRegion(t *testing.T) {
	var warn bytes.Buffer
	p := fanOutProvider(&warn, "us-east-1", "eu-west-1", "ap-south-1", "sa-east-1")

	var mu sync.Mutex
	seen := map[string]int{}
	_, err := eachRegion(context.Background(), p, func(_ context.Context, rp *Provider) ([]string, error) {
		mu.Lock()
		seen[rp.cfg.Region]++
		mu.Unlock()
		return []string{rp.cfg.Region}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(seen) != 4 {
		t.Errorf("saw %d distinct regions, want 4", len(seen))
	}
	for region, n := range seen {
		if n != 1 {
			t.Errorf("region %s scanned %d times, want 1", region, n)
		}
	}
}

// A single-region scan still has to bind a client to that region. Reading the
// configured region and labelling the result with the requested one turns
// `--regions eu-west-1` into a us-west-2 scan wearing the wrong name — and an
// empty answer then reads as an empty region rather than an unread one.
func TestEachRegion_SingleRequestedRegionIsBound(t *testing.T) {
	var warn bytes.Buffer
	p := fanOutProvider(&warn, "us-east-1", "eu-west-1")
	p.regions = []string{"eu-west-1"} // configured region stays us-west-2

	got := collectRegions(t, p)

	if len(got) != 1 || got[0] != "eu-west-1" {
		t.Errorf("scanned %v, want [eu-west-1] — the requested region, not the configured us-west-2", got)
	}
}

func TestEachRegion_SingleRegionMatchingConfigStillScansOnce(t *testing.T) {
	var warn bytes.Buffer
	p := fanOutProvider(&warn, "us-west-2")

	var calls int
	got, err := eachRegion(context.Background(), p, func(_ context.Context, rp *Provider) ([]string, error) {
		calls++
		return []string{rp.cfg.Region}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 || len(got) != 1 || got[0] != "us-west-2" {
		t.Errorf("calls=%d got=%v, want one scan of us-west-2", calls, got)
	}
}

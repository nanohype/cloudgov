package cloud

import (
	"strings"
	"testing"
)

// One envelope, several providers: the report can claim only the period every
// contributing provider covered.
//
// Reporting the widest would assert coverage the narrowest never had, and a
// finding derived from the narrow provider would sit under a window field saying
// the scan looked further back than it did. Understating is the direction that
// cannot mislead an operator into removing access that is in use.
func TestNarrowestWindow(t *testing.T) {
	tests := []struct {
		name         string
		windows      []ScanWindow
		wantObserved int
		wantLimited  string
	}{
		{
			name: "the narrowest provider bounds the report",
			windows: []ScanWindow{
				{RequestedDays: 365, ObservedDays: 365},
				{RequestedDays: 365, ObservedDays: 90, LimitedBy: "aws"},
			},
			wantObserved: 90,
			wantLimited:  "aws",
		},
		{
			name: "order does not decide it",
			windows: []ScanWindow{
				{RequestedDays: 365, ObservedDays: 90, LimitedBy: "aws"},
				{RequestedDays: 365, ObservedDays: 365},
			},
			wantObserved: 90,
			wantLimited:  "aws",
		},
		{
			// Nothing bounded it, so nothing is named. A limited_by on a window
			// that was covered in full would send a reader looking for a
			// narrowing that did not happen.
			name: "every provider covered the request",
			windows: []ScanWindow{
				{RequestedDays: 90, ObservedDays: 90},
				{RequestedDays: 90, ObservedDays: 90},
			},
			wantObserved: 90,
		},
		{
			name:         "one provider",
			windows:      []ScanWindow{{RequestedDays: 30, ObservedDays: 30}},
			wantObserved: 30,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NarrowestWindow(tc.windows)
			if got.ObservedDays != tc.wantObserved {
				t.Errorf("observed = %d, want %d", got.ObservedDays, tc.wantObserved)
			}
			if got.LimitedBy != tc.wantLimited {
				t.Errorf("limited_by = %q, want %q", got.LimitedBy, tc.wantLimited)
			}
			for _, w := range tc.windows {
				if got.ObservedDays > w.ObservedDays {
					t.Errorf("the merged window claims %d days over a provider that covered %d",
						got.ObservedDays, w.ObservedDays)
				}
			}
		})
	}
}

// Describe is what a finding's prose is rendered from, so it carries the covered
// window in both cases and says so when the two differ.
func TestScanWindowDescribe(t *testing.T) {
	full := ScanWindow{RequestedDays: 90, ObservedDays: 90}
	if got := full.Describe(); got != "the last 90 days" {
		t.Errorf("Describe() = %q", got)
	}
	if full.Short() {
		t.Error("a window covered in full reports as short")
	}

	short := ScanWindow{RequestedDays: 365, ObservedDays: 90, LimitedBy: "aws"}
	if !short.Short() {
		t.Fatal("a narrowed window does not report as short")
	}
	got := short.Describe()
	for _, want := range []string{"90", "365", "aws"} {
		if !strings.Contains(got, want) {
			t.Errorf("Describe() = %q, which does not carry %q — a reader of the sentence "+
				"cannot tell the window was narrowed or by what", got, want)
		}
	}
}

// fixedLimit is a provider declaring a retention bound; unlimited declares none.
type fixedLimit struct{ days int }

func (f fixedLimit) MaxLookbackDays() int { return f.days }

type unlimited struct{}

// The scanner has no retention number of its own; it asks the providers it was
// given. This is that ask, and it takes the tightest bound rather than any.
//
// A scan reading several providers can claim only the window every one of them
// could answer for, so the narrowest bound wins. Taking the widest — or the first
// — would let one long-retention provider grant coverage the others never had.
func TestLookbackLimit(t *testing.T) {
	tests := []struct {
		name      string
		providers []any
		want      int
	}{
		{
			name:      "the tightest bound wins",
			providers: []any{fixedLimit{365}, fixedLimit{90}, fixedLimit{180}},
			want:      90,
		},
		{
			name:      "order does not decide it",
			providers: []any{fixedLimit{90}, fixedLimit{365}},
			want:      90,
		},
		{
			// A provider that declares nothing imposes nothing. Retention belongs
			// to the source, and a source that does not say has none applied here
			// rather than inheriting a neighbour's.
			name:      "a provider declaring no bound is ignored",
			providers: []any{unlimited{}, fixedLimit{90}},
			want:      90,
		},
		{
			name:      "nothing declares a bound",
			providers: []any{unlimited{}, unlimited{}},
			want:      0,
		},
		{
			// Zero means unbounded, so a provider returning it must not become the
			// tightest bound and clamp every window to nothing.
			name:      "a declared zero is not a bound of zero",
			providers: []any{fixedLimit{0}, fixedLimit{90}},
			want:      90,
		},
		{
			name:      "no providers",
			providers: nil,
			want:      0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := LookbackLimit(tc.providers); got != tc.want {
				t.Errorf("LookbackLimit = %d, want %d", got, tc.want)
			}
		})
	}
}

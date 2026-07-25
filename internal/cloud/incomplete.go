package cloud

// IncompleteReporter is implemented by a provider that tracks observations it
// could not complete — a paginator that failed partway, a resource it was denied
// on, a call that throttled out.
//
// This exists because "no findings" and "nothing found" are not the same
// statement, and a scanner cannot tell them apart from the outside. A denied
// GetBucketVersioning looks exactly like a versioned bucket if the error is
// dropped. cloudgov's exit code is consumed as merge-gate evidence where 0
// affirmatively supports approval, so a scan that could not read part of an
// account has to say so rather than report the unread part as clean.
//
// Commands type-assert on this after a scan; a provider that never skips
// anything need not implement it.
type IncompleteReporter interface {
	// Incomplete returns one message per observation that could not be
	// completed, or nil when the run saw everything it was asked to.
	Incomplete() []string
}

// Incomplete returns the merged incompletions of every provider in the slice
// that reports them. Scanners take a slice of providers, so commands need the
// union rather than any single provider's view.
func Incomplete[T any](providers []T) []string {
	var out []string
	for _, p := range providers {
		if r, ok := any(p).(IncompleteReporter); ok {
			out = append(out, r.Incomplete()...)
		}
	}
	return out
}

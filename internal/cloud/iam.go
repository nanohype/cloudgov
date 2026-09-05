package cloud

import (
	"context"
	"fmt"
	"time"
)

// ScanWindow is the audit-log period a scan covered.
//
// RequestedDays and ObservedDays are separate fields because they answer
// different questions and one number cannot: a scan asked for 365 days over a
// source holding 90 covers 90, and a reader given only the request cannot tell
// that from a source that held all 365. Every claim a scan makes about non-use
// rests on ObservedDays.
//
// It travels in the report so a consumer can read the window rather than parse
// it out of a sentence. A finding's prose is rendered from this value, so the
// two cannot disagree.
type ScanWindow struct {
	// RequestedDays is the lookback the caller asked for.
	RequestedDays int `json:"requested_days"`
	// ObservedDays is the lookback the audit log could answer for. Equal to
	// RequestedDays when nothing bounded it.
	ObservedDays int `json:"observed_days"`
	// LimitedBy names the provider whose retention bound the window, empty when
	// the requested window was covered in full.
	LimitedBy string `json:"limited_by,omitempty"`
}

// Short reports whether the scan covered less than it was asked for.
func (w ScanWindow) Short() bool { return w.ObservedDays < w.RequestedDays }

// Describe renders the window as the period a finding can claim, so prose about
// non-use states what was looked at rather than what was asked for.
func (w ScanWindow) Describe() string {
	if w.Short() {
		return fmt.Sprintf("the %d day(s) this scan covered (%d requested; %s retains no more)",
			w.ObservedDays, w.RequestedDays, w.LimitedBy)
	}
	return fmt.Sprintf("the last %d days", w.ObservedDays)
}

// NarrowestWindow merges the windows of the providers a scan read into the one
// the report can claim.
//
// A run over several providers merges their findings into one envelope, and the
// envelope can only assert the period every contributing provider covered:
// reporting the widest would claim coverage the narrowest never had. So
// ObservedDays is the smallest, and LimitedBy names the provider that bound it.
//
// A finding from a wider provider rests on more than this says, and its own
// Detail carries that. Understating is the direction that cannot mislead an
// operator into removing access.
func NarrowestWindow(windows []ScanWindow) ScanWindow {
	var out ScanWindow
	for _, w := range windows {
		if w.RequestedDays > out.RequestedDays {
			out.RequestedDays = w.RequestedDays
		}
		if out.ObservedDays == 0 || w.ObservedDays < out.ObservedDays {
			out.ObservedDays = w.ObservedDays
			out.LimitedBy = w.LimitedBy
		}
	}
	if !out.Short() {
		out.LimitedBy = ""
	}
	return out
}

// LookbackLimiter is implemented by a provider whose audit-log source retains
// only a bounded history.
//
// Retention is a property of the source, not of this tool: CloudTrail's Event
// history holds 90 days of management events, while the same account read
// through CloudTrail Lake or an Athena-backed trail has whatever its retention
// says. A scanner that hardcoded a number would be wrong for the second, so the
// provider declares its own and a provider that declares none is treated as
// unbounded.
//
// The limit is in days to match the window a caller asks for.
type LookbackLimiter interface {
	// MaxLookbackDays returns the furthest back this provider's audit log can
	// answer for, or 0 when it is not bounded.
	MaxLookbackDays() int
}

// LookbackLimit returns the tightest bound declared by any provider in the
// slice, or 0 when none declares one.
//
// Tightest rather than any: a scanner reading several providers can only claim
// the window every one of them could answer for, and reporting the widest would
// assert coverage the narrowest never had.
func LookbackLimit[T any](providers []T) int {
	limit := 0
	for _, p := range providers {
		l, ok := any(p).(LookbackLimiter)
		if !ok {
			continue
		}
		if d := l.MaxLookbackDays(); d > 0 && (limit == 0 || d < limit) {
			limit = d
		}
	}
	return limit
}

// IAMProvider fetches IAM data and computes minimal policies.
type IAMProvider interface {
	Provider
	ListPrincipals(ctx context.Context) ([]Principal, error)
	GrantedPermissions(ctx context.Context, p Principal) ([]Permission, error)
	UsedPermissions(ctx context.Context, p Principal, since time.Time) ([]Permission, error)
	MinimalPolicy(ctx context.Context, p Principal, used []Permission) (Policy, error)
}

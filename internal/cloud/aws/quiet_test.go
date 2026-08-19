package aws

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestWarnf_WritesToWarnw(t *testing.T) {
	var buf bytes.Buffer
	p := &Provider{warnw: &buf}
	p.warnf("warn: %s\n", "boom")
	if got := buf.String(); got != "warn: boom\n" {
		t.Errorf("warnf wrote %q, want %q", got, "warn: boom\n")
	}
}

func TestWithQuiet_RoutesWarningsToDiscard(t *testing.T) {
	p := &Provider{}
	WithQuiet(true)(p)
	if p.warnw != io.Discard {
		t.Error("WithQuiet(true) should route provider warnings to io.Discard")
	}

	p2 := &Provider{}
	WithQuiet(false)(p2)
	if p2.warnw != nil {
		t.Error("WithQuiet(false) should leave warnw unset (warnf falls back to os.Stderr)")
	}
}

// TestQuiet_SilencesTheOutputNotTheRecord pins the property the whole incomplete
// contract rests on: --quiet is a display setting, not a scope setting.
//
// If quiet suppressed the record rather than the copy, then `--quiet` would be a
// flag that silently converts a partial read into a clean one — the same shape as
// reporting a denied HeadBucket as DELETED, one level up. Scripts run with
// --quiet precisely because they consume the JSON, so that is the run where the
// record matters most.
func TestQuiet_SilencesTheOutputNotTheRecord(t *testing.T) {
	p := &Provider{}
	WithQuiet(true)(p)

	p.warnf("warn: describe regions: %v; scanned us-east-1 only\n", "AccessDenied")

	incomplete := p.Incomplete()
	if len(incomplete) != 1 {
		t.Fatalf("a quiet run must still record what it could not read, got %d observations", len(incomplete))
	}
	if !strings.Contains(incomplete[0], "AccessDenied") {
		t.Errorf("recorded observation should carry the cause, got %q", incomplete[0])
	}
}

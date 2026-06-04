package aws

import (
	"bytes"
	"io"
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

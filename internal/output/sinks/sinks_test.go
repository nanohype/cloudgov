package sinks

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDigestWorstSeverity(t *testing.T) {
	tests := []struct {
		d    Digest
		want string
	}{
		{Digest{Critical: 1}, "CRITICAL"},
		{Digest{High: 1}, "HIGH"},
		{Digest{Medium: 1}, "MEDIUM"},
		{Digest{Low: 1}, "LOW"},
		{Digest{}, "INFO"},
		{Digest{High: 5, Low: 100}, "HIGH"}, // worst, not most-frequent
	}
	for _, tt := range tests {
		got := tt.d.WorstSeverity()
		if got != tt.want {
			t.Errorf("got %q, want %q for %+v", got, tt.want, tt.d)
		}
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		specs   []string
		wantN   int
		wantErr bool
	}{
		{"empty list", nil, 0, false},
		{"single slack", []string{"slack:https://hooks.slack.com/services/x"}, 1, false},
		{"single webhook", []string{"webhook:https://example.com/h"}, 1, false},
		{"single pagerduty", []string{"pagerduty:routing-key-123"}, 1, false},
		{"all three", []string{
			"slack:https://hooks.slack.com/x",
			"webhook:https://example.com/h",
			"pagerduty:rk",
		}, 3, false},
		{"missing prefix", []string{"https://example.com"}, 0, true},
		{"unknown kind", []string{"discord:https://example.com"}, 0, true},
		{"empty url", []string{"slack:"}, 0, true},
		{"whitespace only", []string{"  "}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss, err := Parse(tt.specs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
			if !tt.wantErr && len(ss) != tt.wantN {
				t.Errorf("got %d sinks, want %d", len(ss), tt.wantN)
			}
		})
	}
}

func TestSendAll_BestEffort(t *testing.T) {
	good := &countingSink{name: "good"}
	bad := &erroringSink{name: "bad", err: errors.New("network down")}
	otherGood := &countingSink{name: "good2"}

	err := SendAll(context.Background(),
		[]Sink{good, bad, otherGood},
		Digest{Source: "test"},
	)
	if err == nil {
		t.Fatal("expected aggregated error")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Errorf("error should name failing sink: %v", err)
	}
	if good.sent != 1 || otherGood.sent != 1 {
		t.Error("good sinks should still have been called despite bad sink failing")
	}
}

func TestSendAll_AllSuccess(t *testing.T) {
	s1, s2 := &countingSink{name: "a"}, &countingSink{name: "b"}
	if err := SendAll(context.Background(), []Sink{s1, s2}, Digest{}); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// ── WebhookSink ────────────────────────────────────────────────────────────

func TestWebhookSink_Success(t *testing.T) {
	var got Digest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method: got %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type: got %q", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := Digest{Source: "test", Provider: "aws", TotalFindings: 5, Critical: 1, High: 4}
	sink := &WebhookSink{URL: srv.URL}
	if err := sink.Send(context.Background(), d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Source != "test" || got.TotalFindings != 5 {
		t.Errorf("unmarshaled digest: %+v", got)
	}
}

func TestWebhookSink_InvalidURL(t *testing.T) {
	sink := &WebhookSink{URL: "not-a-url"}
	err := sink.Send(context.Background(), Digest{})
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestWebhookSink_5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server down"))
	}))
	defer srv.Close()
	sink := &WebhookSink{URL: srv.URL}
	err := sink.Send(context.Background(), Digest{})
	if err == nil {
		t.Fatal("expected error from 5xx")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code: %v", err)
	}
}

// ── SlackSink ──────────────────────────────────────────────────────────────

func TestSlackSink_PayloadStructure(t *testing.T) {
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := Digest{
		Source:    "matlock audit",
		Provider:  "aws",
		Timestamp: time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
		Critical:  2, High: 3, TotalFindings: 5,
		Domains: []string{"iam", "storage"},
		Top: []Finding{
			{Severity: "CRITICAL", Type: "ADMIN_ACCESS", Provider: "aws", Resource: "admin-role", Detail: "* on *"},
		},
		ReportURL: "https://report.example.com/123",
	}
	sink := &SlackSink{WebhookURL: srv.URL}
	if err := sink.Send(context.Background(), d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("payload not valid JSON: %v\n%s", err, raw)
	}
	if payload["text"] == nil {
		t.Error("payload should include text fallback")
	}
	blocks, ok := payload["blocks"].([]interface{})
	if !ok || len(blocks) == 0 {
		t.Fatal("payload should include blocks")
	}
	// Check that the body contains expected strings
	body := string(raw)
	for _, want := range []string{"matlock audit", "aws", "iam", "storage", "admin-role", "report.example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("slack payload missing %q", want)
		}
	}
}

func TestSlackSink_InvalidURL(t *testing.T) {
	sink := &SlackSink{WebhookURL: ""}
	if err := sink.Send(context.Background(), Digest{}); err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestSlackSink_TruncatesTopFindings(t *testing.T) {
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := Digest{Source: "audit", Provider: "aws"}
	for i := 0; i < 25; i++ {
		d.Top = append(d.Top, Finding{Severity: "HIGH", Resource: "x", Detail: "y"})
	}
	sink := &SlackSink{WebhookURL: srv.URL}
	_ = sink.Send(context.Background(), d)
	// Count bullet markers; should be 10, not 25.
	body := string(raw)
	count := strings.Count(body, "[HIGH]")
	if count != 10 {
		t.Errorf("expected 10 top findings rendered, got %d", count)
	}
}

func TestSeverityEmoji(t *testing.T) {
	tests := map[string]string{
		"CRITICAL": ":rotating_light:",
		"HIGH":     ":warning:",
		"MEDIUM":   ":large_yellow_circle:",
		"LOW":      ":large_blue_circle:",
		"INFO":     ":information_source:",
		"weird":    ":information_source:",
	}
	for sev, want := range tests {
		got := severityEmoji(sev)
		if got != want {
			t.Errorf("severityEmoji(%q): got %q, want %q", sev, got, want)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 100, "short"},
		{"hello world", 8, "hello..."},
		{"abc", 3, "abc"},
		{"abc", 2, "ab"},
	}
	for _, tt := range tests {
		got := truncate(tt.in, tt.n)
		if got != tt.want {
			t.Errorf("truncate(%q,%d): got %q, want %q", tt.in, tt.n, got, tt.want)
		}
	}
}

// ── PagerDutySink ──────────────────────────────────────────────────────────

func TestPagerDutySink_OnlyFiresOnCritOrHigh(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	sink := &PagerDutySink{RoutingKey: "rk", URL: srv.URL}
	// medium-only → no page
	_ = sink.Send(context.Background(), Digest{Medium: 10})
	if called {
		t.Error("medium-only digest should not trigger PagerDuty")
	}

	called = false
	_ = sink.Send(context.Background(), Digest{High: 1})
	if !called {
		t.Error("high digest should trigger PagerDuty")
	}

	called = false
	_ = sink.Send(context.Background(), Digest{Critical: 1})
	if !called {
		t.Error("critical digest should trigger PagerDuty")
	}
}

func TestPagerDutySink_PayloadShape(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	sink := &PagerDutySink{RoutingKey: "my-routing-key", URL: srv.URL}
	d := Digest{
		Source: "matlock audit", Provider: "aws", Critical: 1,
		TotalFindings: 1, Domains: []string{"iam"},
	}
	if err := sink.Send(context.Background(), d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got["routing_key"] != "my-routing-key" {
		t.Errorf("routing_key: got %v", got["routing_key"])
	}
	if got["event_action"] != "trigger" {
		t.Errorf("event_action: got %v", got["event_action"])
	}
	payload, _ := got["payload"].(map[string]interface{})
	if payload == nil {
		t.Fatal("missing payload")
	}
	if payload["severity"] != "critical" {
		t.Errorf("severity: got %v", payload["severity"])
	}
}

func TestPagerDutySink_MissingRoutingKey(t *testing.T) {
	sink := &PagerDutySink{}
	err := sink.Send(context.Background(), Digest{Critical: 1})
	if err == nil {
		t.Fatal("expected error for missing routing key")
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

type countingSink struct {
	name string
	sent int
}

func (c *countingSink) Name() string { return c.name }
func (c *countingSink) Send(_ context.Context, _ Digest) error {
	c.sent++
	return nil
}

type erroringSink struct {
	name string
	err  error
}

func (e *erroringSink) Name() string                           { return e.name }
func (e *erroringSink) Send(_ context.Context, _ Digest) error { return e.err }

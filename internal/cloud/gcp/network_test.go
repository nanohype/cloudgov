package gcp

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/api/compute/v1"

	"github.com/stxkxs/matlock/internal/cloud"
)

func TestAuditNetwork(t *testing.T) {
	tests := []struct {
		name    string
		fws     []*compute.Firewall
		wantSev []cloud.Severity
	}{
		{
			name: "open SSH from internet is critical",
			fws: []*compute.Firewall{{
				Name: "ssh-open", SourceRanges: []string{"0.0.0.0/0"},
				Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}},
			}},
			wantSev: []cloud.Severity{cloud.SeverityCritical},
		},
		{
			name: "all-traffic allow is critical",
			fws: []*compute.Firewall{{
				Name: "open-all", SourceRanges: []string{"0.0.0.0/0"},
				Allowed: []*compute.FirewallAllowed{{IPProtocol: "all"}},
			}},
			wantSev: []cloud.Severity{cloud.SeverityCritical},
		},
		{
			name: "HTTP/HTTPS on 80/443 is allowed",
			fws: []*compute.Firewall{{
				Name: "web", SourceRanges: []string{"0.0.0.0/0"},
				Allowed: []*compute.FirewallAllowed{
					{IPProtocol: "tcp", Ports: []string{"80"}},
					{IPProtocol: "tcp", Ports: []string{"443"}},
				},
			}},
			wantSev: nil,
		},
		{
			name: "disabled rule is ignored",
			fws: []*compute.Firewall{{
				Name: "off", Disabled: true, SourceRanges: []string{"0.0.0.0/0"},
				Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}},
			}},
			wantSev: nil,
		},
		{
			name: "private source is not flagged",
			fws: []*compute.Firewall{{
				Name: "internal", SourceRanges: []string{"10.0.0.0/8"},
				Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}},
			}},
			wantSev: nil,
		},
		{
			name: "open all egress is medium",
			fws: []*compute.Firewall{{
				Name: "egress", Direction: "EGRESS", DestinationRanges: []string{"0.0.0.0/0"},
				Allowed: []*compute.FirewallAllowed{{IPProtocol: "all"}},
			}},
			wantSev: []cloud.Severity{cloud.SeverityMedium},
		},
		{
			name: "non-sensitive port open to internet is high",
			fws: []*compute.Firewall{{
				Name: "x", SourceRanges: []string{"0.0.0.0/0"},
				Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"8080"}}},
			}},
			wantSev: []cloud.Severity{cloud.SeverityHigh},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{projectID: "p", compute: &mockCompute{firewalls: tt.fws}}
			got, err := p.AuditNetwork(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.wantSev) {
				t.Fatalf("findings: got %d, want %d (%v)", len(got), len(tt.wantSev), got)
			}
			for i := range got {
				if got[i].Severity != tt.wantSev[i] {
					t.Errorf("finding[%d] severity: got %v, want %v", i, got[i].Severity, tt.wantSev[i])
				}
			}
		})
	}
}

func TestAuditNetwork_NoProject(t *testing.T) {
	p := &Provider{compute: &mockCompute{}}
	_, err := p.AuditNetwork(context.Background())
	if err == nil {
		t.Fatal("expected error for missing project")
	}
}

func TestAuditNetwork_Error(t *testing.T) {
	p := &Provider{projectID: "p", compute: &mockCompute{fwErr: errors.New("api")}}
	_, err := p.AuditNetwork(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		s    string
		f, t int
	}{
		{"22", 22, 22},
		{"22-80", 22, 80},
	}
	for _, tt := range tests {
		f, to := parsePortRange(tt.s)
		if f != tt.f || to != tt.t {
			t.Errorf("%q: got (%d, %d), want (%d, %d)", tt.s, f, to, tt.f, tt.t)
		}
	}
}

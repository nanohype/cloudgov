package providers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// fakeProvider implements cloud.Provider plus one capability (OrphansProvider).
// It deliberately does NOT implement IAMProvider, so capability filtering is
// observable.
type fakeProvider struct{ name string }

func (f fakeProvider) Name() string                { return f.name }
func (f fakeProvider) Detect(context.Context) bool { return true }
func (f fakeProvider) ListOrphans(context.Context) ([]cloud.OrphanResource, error) {
	return nil, nil
}

type fakeFactory struct {
	name   string
	detect bool
	newErr error
}

func (f fakeFactory) Name() string                { return f.name }
func (f fakeFactory) Detect(context.Context) bool { return f.detect }
func (f fakeFactory) New(context.Context) (cloud.Provider, error) {
	if f.newErr != nil {
		return nil, f.newErr
	}
	return fakeProvider{name: f.name}, nil
}

func TestAvailable_SkipsUndetected(t *testing.T) {
	reg := NewRegistry(
		fakeFactory{name: "a", detect: true},
		fakeFactory{name: "b", detect: false}, // not detected → skipped
	)
	got := reg.Available(context.Background())
	if len(got) != 1 || got[0].Name() != "a" {
		t.Fatalf("want [a], got %v", got)
	}
}

func TestAvailable_SkipsNewError(t *testing.T) {
	reg := NewRegistry(
		fakeFactory{name: "a", detect: true, newErr: errors.New("boom")}, // detected but fails → skipped
		fakeFactory{name: "b", detect: true},
	)
	got := reg.Available(context.Background())
	if len(got) != 1 || got[0].Name() != "b" {
		t.Fatalf("want [b], got %v", got)
	}
}

// The pluggability proof: a brand-new provider factory is picked up by Capable
// with no change to any command — registering the factory is the only edit.
func TestCapable_PicksUpNewProviderWithNoCommandChanges(t *testing.T) {
	reg := NewRegistry(fakeFactory{name: "newcloud", detect: true})
	got, err := Capable[cloud.OrphansProvider](context.Background(), reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Name() != "newcloud" {
		t.Fatalf("want [newcloud] resolved as OrphansProvider, got %v", got)
	}
}

func TestCapable_FiltersByCapability(t *testing.T) {
	// fakeProvider implements OrphansProvider but not IAMProvider.
	reg := NewRegistry(fakeFactory{name: "a", detect: true})
	if _, err := Capable[cloud.IAMProvider](context.Background(), reg); err == nil {
		t.Fatal("want error: available provider lacks IAM capability")
	}
}

func TestCapable_NoProviderDetected(t *testing.T) {
	reg := NewRegistry(fakeFactory{name: "a", detect: false})
	if _, err := Capable[cloud.OrphansProvider](context.Background(), reg); err == nil {
		t.Fatal("want error when no provider is available")
	}
}

// Default is the single place provider construction is configured, so the
// options a command passes have to reach the factory it builds. A region
// restriction that stopped here would leave every scan sweeping the whole
// account while the flag reported otherwise.
func TestDefault_OptionsReachTheAWSFactory(t *testing.T) {
	tests := []struct {
		name        string
		opts        []Option
		wantProfile string
		wantQuiet   bool
		wantRegions []string
	}{
		{"defaults", nil, "", false, nil},
		{"profile", []Option{WithProfile("stxkxs")}, "stxkxs", false, nil},
		{"quiet", []Option{WithQuiet(true)}, "", true, nil},
		{"regions", []Option{WithRegions([]string{"us-east-1", "eu-west-1"})}, "", false, []string{"us-east-1", "eu-west-1"}},
		{
			"combined",
			[]Option{WithProfile("p"), WithQuiet(true), WithRegions([]string{"ap-south-1"})},
			"p", true, []string{"ap-south-1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := Default(tt.opts...)
			if len(reg.factories) != 1 {
				t.Fatalf("got %d factories, want 1", len(reg.factories))
			}
			f, ok := reg.factories[0].(awsFactory)
			if !ok {
				t.Fatalf("got %T, want awsFactory", reg.factories[0])
			}
			if f.profile != tt.wantProfile {
				t.Errorf("profile = %q, want %q", f.profile, tt.wantProfile)
			}
			if f.quiet != tt.wantQuiet {
				t.Errorf("quiet = %v, want %v", f.quiet, tt.wantQuiet)
			}
			if strings.Join(f.regions, ",") != strings.Join(tt.wantRegions, ",") {
				t.Errorf("regions = %v, want %v", f.regions, tt.wantRegions)
			}
			// Detect and New must configure providers identically, or a
			// credential check and the scan that follows it disagree.
			if got := len(f.opts()); got != 2 {
				t.Errorf("opts() returned %d options, want 2", got)
			}
		})
	}
}

func TestAWSFactory_Name(t *testing.T) {
	if got := newAWSFactory("", false, nil).Name(); got != "aws" {
		t.Errorf("Name() = %q, want aws", got)
	}
}

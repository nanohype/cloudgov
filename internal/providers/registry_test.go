package providers

import (
	"context"
	"errors"
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

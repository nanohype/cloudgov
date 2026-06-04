// Package providers resolves the cloud providers available in the current
// environment. It is the single seam through which commands obtain providers:
// rather than each command hardcoding one cloud, it asks the registry for every
// provider whose credentials are present that implements the capability it needs.
//
// Adding a cloud is "implement the cloud.Provider capability interfaces in
// internal/cloud/<cloud> + register a Factory in Default" — no command changes.
// Today only AWS is registered; GCP/Azure are commented slots in Default.
package providers

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/nanohype/cloudgov/internal/cloud"
	cloudaws "github.com/nanohype/cloudgov/internal/cloud/aws"
)

// Factory builds a provider after a cheap credential check. Detect reports
// whether credentials are present (no API calls beyond credential resolution);
// New constructs the provider's SDK clients.
type Factory interface {
	Name() string
	Detect(ctx context.Context) bool
	New(ctx context.Context) (cloud.Provider, error)
}

// Registry holds the provider factories to consider. Construct it explicitly
// (NewRegistry / Default) — there is no package-level mutable registry.
type Registry struct {
	factories []Factory
}

// NewRegistry returns a Registry over the given factories.
func NewRegistry(factories ...Factory) *Registry {
	return &Registry{factories: factories}
}

// Available returns every provider whose credentials are detected. A factory
// that detects but fails to construct is skipped with a warning rather than
// failing the whole run, so one misconfigured cloud doesn't sink the others.
func (r *Registry) Available(ctx context.Context) []cloud.Provider {
	var out []cloud.Provider
	for _, f := range r.factories {
		if !f.Detect(ctx) {
			continue
		}
		p, err := f.New(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s credentials detected but initialization failed: %v\n", f.Name(), err)
			continue
		}
		out = append(out, p)
	}
	return out
}

// Capable returns every available provider implementing capability T (e.g.
// cloud.CostProvider). It errors only when no available provider offers it.
func Capable[T any](ctx context.Context, r *Registry) ([]T, error) {
	var out []T
	for _, p := range r.Available(ctx) {
		if c, ok := p.(T); ok {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no cloud provider detected")
	}
	return out, nil
}

// Option configures the default registry.
type Option func(*options)

type options struct {
	profile string
}

// WithProfile selects a named credentials profile for providers that support
// one (AWS named profiles today).
func WithProfile(profile string) Option {
	return func(o *options) { o.profile = profile }
}

// Default builds the registry of all built-in providers — the single place a
// new cloud is registered.
func Default(opts ...Option) *Registry {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return NewRegistry(
		newAWSFactory(o.profile),
		// gcp/azure factories — register here once implemented; the capability
		// interfaces and finding.Provider field already accommodate them.
	)
}

// Resolve returns every default-registry provider implementing capability T.
// This is the one-liner the command resolvers delegate to.
func Resolve[T any](ctx context.Context, opts ...Option) ([]T, error) {
	return Capable[T](ctx, Default(opts...))
}

// awsFactory adapts the AWS provider to the Factory contract.
type awsFactory struct {
	profile string
}

// newAWSFactory builds the AWS factory for the given named profile ("" = the
// default credential chain).
func newAWSFactory(profile string) awsFactory {
	return awsFactory{profile: profile}
}

func (f awsFactory) Name() string { return "aws" }

func (f awsFactory) Detect(ctx context.Context) bool {
	p, err := cloudaws.NewWithProfile(ctx, f.profile)
	return err == nil && p.Detect(ctx)
}

func (f awsFactory) New(ctx context.Context) (cloud.Provider, error) {
	return cloudaws.NewWithProfile(ctx, f.profile)
}

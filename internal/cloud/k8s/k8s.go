// Package k8s implements the cloudgov provider interfaces for Kubernetes clusters.
//
// Detection works against any cluster reachable via the standard kubeconfig
// chain ($KUBECONFIG → ~/.kube/config → in-cluster service-account token).
//
// Per-domain client surfaces (rbacAPI, etc.) are interface-typed adapters
// around the real *kubernetes.Clientset. Tests construct Provider directly
// with hand-written mocks satisfying the same interfaces — same pattern as
// the AWS provider package.
package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// k8sRequestTimeout bounds a single Kubernetes API request. The command's
// signal-aware context lets a user Ctrl-C an interactive run, but an unattended
// one — a CI gate, an MCP tool call — has nobody to press it, so an apiserver
// that accepts the connection and never answers would hang the scan with no
// ceiling. This package issues only List and Get calls, never a watch or a log
// stream, so a per-request deadline is safe to apply to every client it builds.
const k8sRequestTimeout = 30 * time.Second

// Option configures how a cluster connection is resolved.
type Option func(*connOptions)

type connOptions struct {
	denyExecCredentials bool
}

// WithoutExecCredentials refuses a kubeconfig whose resolved user obtains
// credentials by running an exec plugin. The plugin's command, arguments and
// environment come from the file, so whoever names the file chooses which
// binary runs inside this process — which holds live cloud credentials. An
// operator naming a path on the command line already has that power. A caller
// that receives the path across a trust boundary does not, and must not inherit
// it by passing the string through.
func WithoutExecCredentials() Option {
	return func(o *connOptions) { o.denyExecCredentials = true }
}

func resolveOptions(opts []Option) connOptions {
	var o connOptions
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

// Provider implements CloudGov's Kubernetes provider interfaces.
type Provider struct {
	clientset   *kubernetes.Clientset
	contextName string
	rbac        rbacAPI
}

// New loads cluster config (kubeconfig or in-cluster) and builds a Provider.
// If kubeconfig is empty, it falls back to $KUBECONFIG, then ~/.kube/config,
// then in-cluster config.
func New(_ context.Context, kubeconfig string, opts ...Option) (*Provider, error) {
	config, contextName, err := loadConfig(kubeconfig, resolveOptions(opts))
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes clientset: %w", err)
	}

	p := &Provider{
		clientset:   clientset,
		contextName: contextName,
	}
	p.rbac = &rbacAdapter{clientset: clientset}
	return p, nil
}

// Clients bundles a typed clientset and a dynamic client from one cluster
// connection, for callers that read custom resources (e.g. Platform CRs)
// alongside core objects.
type Clients struct {
	Typed       kubernetes.Interface
	Dynamic     dynamic.Interface
	ContextName string
}

// NewClients resolves cluster config exactly as New does and returns both a
// typed clientset and a dynamic client.
func NewClients(_ context.Context, kubeconfig string, opts ...Option) (*Clients, error) {
	config, contextName, err := loadConfig(kubeconfig, resolveOptions(opts))
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	typed, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes clientset: %w", err)
	}
	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("build dynamic client: %w", err)
	}
	return &Clients{Typed: typed, Dynamic: dyn, ContextName: contextName}, nil
}

// Name returns the provider identifier.
func (p *Provider) Name() string { return "k8s" }

// ContextName returns the active kubeconfig context, or "" for in-cluster.
func (p *Provider) ContextName() string { return p.contextName }

// Detect returns true when a kubeconfig file is reachable or in-cluster
// credentials are present.
func (p *Provider) Detect(_ context.Context) bool {
	if os.Getenv("KUBECONFIG") != "" {
		return true
	}
	if home, _ := os.UserHomeDir(); home != "" {
		if _, err := os.Stat(filepath.Join(home, ".kube", "config")); err == nil {
			return true
		}
	}
	// In-cluster service-account token mount
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}
	return false
}

// loadConfig resolves a *rest.Config from explicit kubeconfig path,
// $KUBECONFIG, ~/.kube/config, or in-cluster config, in that order.
// The returned contextName is empty for in-cluster. Every config it returns
// carries k8sRequestTimeout.
func loadConfig(kubeconfig string, opts connOptions) (*rest.Config, string, error) {
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}
	if kubeconfig == "" {
		if home, _ := os.UserHomeDir(); home != "" {
			candidate := filepath.Join(home, ".kube", "config")
			if _, err := os.Stat(candidate); err == nil {
				kubeconfig = candidate
			}
		}
	}

	if kubeconfig == "" {
		// Try in-cluster.
		config, err := rest.InClusterConfig()
		if err != nil {
			return nil, "", fmt.Errorf("no kubeconfig and no in-cluster credentials: %w", err)
		}
		config.Timeout = k8sRequestTimeout
		return config, "", nil
	}

	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	overrides := &clientcmd.ConfigOverrides{}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)

	rawConfig, err := loader.RawConfig()
	if err != nil {
		return nil, "", fmt.Errorf("read kubeconfig: %w", err)
	}
	contextName := rawConfig.CurrentContext

	config, err := loader.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("build client config: %w", err)
	}
	if opts.denyExecCredentials && config.ExecProvider != nil {
		return nil, "", fmt.Errorf(
			"kubeconfig %s authenticates by running %q; this caller may not name a kubeconfig that executes a credential plugin",
			kubeconfig, config.ExecProvider.Command)
	}
	config.Timeout = k8sRequestTimeout
	return config, contextName, nil
}

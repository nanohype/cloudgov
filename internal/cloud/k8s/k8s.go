// Package k8s implements the matlock provider interfaces for Kubernetes clusters.
//
// Detection works against any cluster reachable via the standard kubeconfig
// chain ($KUBECONFIG → ~/.kube/config → in-cluster service-account token).
//
// Per-domain client surfaces (rbacAPI, etc.) are interface-typed adapters
// around the real *kubernetes.Clientset. Tests construct Provider directly
// with hand-written mocks satisfying the same interfaces — same pattern as
// the AWS/GCP/Azure provider packages.
package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Provider implements Matlock's Kubernetes provider interfaces.
type Provider struct {
	clientset   *kubernetes.Clientset
	contextName string
	rbac        rbacAPI
}

// New loads cluster config (kubeconfig or in-cluster) and builds a Provider.
// If kubeconfig is empty, it falls back to $KUBECONFIG, then ~/.kube/config,
// then in-cluster config.
func New(_ context.Context, kubeconfig string) (*Provider, error) {
	config, contextName, err := loadConfig(kubeconfig)
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
// The returned contextName is empty for in-cluster.
func loadConfig(kubeconfig string) (*rest.Config, string, error) {
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
	return config, contextName, nil
}

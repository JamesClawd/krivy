// Package kube builds the Kubernetes client used by the controller.
package kube

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Options select how to reach the API server.
type Options struct {
	// Kubeconfig path; empty means in-cluster config.
	Kubeconfig string
	// Context must be set explicitly when Kubeconfig is used, so a developer
	// never scans (or creates Jobs in) whatever context happens to be current.
	Context   string
	UserAgent string
}

// RestConfig resolves the client configuration.
func RestConfig(o Options) (*rest.Config, string, error) {
	if o.Kubeconfig == "" {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, "", fmt.Errorf("in-cluster config (set kubernetes.kubeconfig for out-of-cluster runs): %w", err)
		}
		return withUA(cfg, o.UserAgent), "in-cluster", nil
	}
	if o.Context == "" {
		return nil, "", fmt.Errorf("kubernetes.context is required when kubernetes.kubeconfig is set")
	}
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: o.Kubeconfig}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: o.Context})
	raw, err := cc.RawConfig()
	if err != nil {
		return nil, "", fmt.Errorf("load kubeconfig %s: %w", o.Kubeconfig, err)
	}
	if _, ok := raw.Contexts[o.Context]; !ok {
		return nil, "", fmt.Errorf("context %q not found in %s", o.Context, o.Kubeconfig)
	}
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, "", err
	}
	return withUA(cfg, o.UserAgent), o.Context, nil
}

// NewClient returns a typed clientset.
func NewClient(o Options) (kubernetes.Interface, string, error) {
	cfg, name, err := RestConfig(o)
	if err != nil {
		return nil, "", err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, "", err
	}
	return cs, name, nil
}

func withUA(c *rest.Config, ua string) *rest.Config {
	if ua != "" {
		c.UserAgent = ua
	}
	c.QPS, c.Burst = 20, 40
	return c
}

// Package discovery lists images used by active Pods via read-only client-go.
package discovery

import "context"

// WorkloadRef identifies a container in a namespaced owner (top-level
// controller such as Deployment/StatefulSet/DaemonSet/CronJob, or the Pod).
type WorkloadRef struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Container string `json:"container"`
	// ContainerType is "container", "init" or "ephemeral".
	ContainerType string `json:"containerType"`
}

// Image is one deduplicated image identity with all workloads using it.
type Image struct {
	// Key is "<repository>@<digest>" when the running digest is known,
	// otherwise the normalized image reference.
	Key        string `json:"key"`
	Repository string `json:"repository"`
	Digest     string `json:"digest,omitempty"`
	// Ref is what the scanner should scan: digest-pinned when possible.
	Ref       string        `json:"ref"`
	Workloads []WorkloadRef `json:"workloads"`
}

// Result of a discovery pass.
type Result struct {
	Images []Image `json:"images"`
	// Warnings are non-fatal issues (e.g. pod without imageID).
	Warnings []string `json:"warnings,omitempty"`
}

// Discoverer lists active images. namespace "" means all namespaces.
type Discoverer interface {
	Discover(ctx context.Context, namespace string) (*Result, error)
}

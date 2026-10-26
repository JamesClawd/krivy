// Package scanner runs one ephemeral Trivy Kubernetes Job per image and
// parses its JSON report.
package scanner

import (
	"context"
	"errors"
	"fmt"
)

// Target is an image to scan.
type Target struct {
	// ScanJobID is the persisted ScanJob ID; used for Job labels/naming.
	ScanJobID string
	ImageKey  string
	ImageRef  string
	// Attempt number (1-based), included in the Job name.
	Attempt int
}

// Vulnerability is one parsed Trivy vulnerability.
type Vulnerability struct {
	VulnerabilityID  string `json:"vulnerabilityId"`
	PkgName          string `json:"pkgName"`
	PkgPath          string `json:"pkgPath,omitempty"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion,omitempty"`
	Severity         string `json:"severity"`
	Title            string `json:"title,omitempty"`
	PrimaryURL       string `json:"primaryUrl,omitempty"`
	// Target is the Trivy result target (e.g. OS layer or lockfile).
	Target string `json:"target,omitempty"`
}

// Result of a successful scan. An empty Vulnerabilities slice is a clean scan.
type Result struct {
	ImageRef        string
	ImageDigest     string
	OS              string
	Vulnerabilities []Vulnerability
	// JobName is the Kubernetes Job that produced the result.
	JobName string
	// Diagnostics is a short human-readable trace (sizes, timings, warnings).
	Diagnostics string
}

// Scanner scans one image, blocking until the scan finishes, fails or ctx is
// cancelled. Implementations must clean up / allow TTL cleanup of Jobs.
type Scanner interface {
	Scan(ctx context.Context, t Target) (*Result, error)
}

// ErrorKind classifies scan failures.
type ErrorKind string

const (
	// KindTimeout: Job exceeded its deadline.
	KindTimeout ErrorKind = "timeout"
	// KindImagePull: Trivy could not find the image (manifest/name unknown).
	KindImagePull ErrorKind = "image_pull"
	// KindRegistryAuth: registry credentials are missing, invalid or were
	// rejected (unauthorized/denied), or a registryAuth Secret is unusable.
	KindRegistryAuth ErrorKind = "registry_auth"
	// KindScanner: Trivy exited non-zero for another reason.
	KindScanner ErrorKind = "scanner"
	// KindOutput: output missing, truncated or invalid JSON.
	KindOutput ErrorKind = "output"
	// KindKubernetes: API error creating/watching the Job.
	KindKubernetes ErrorKind = "kubernetes"
	// KindScheduling: Pod could not be scheduled / scanner image pull failed.
	KindScheduling ErrorKind = "scheduling"
)

// Error is a classified scan failure.
type Error struct {
	Kind      ErrorKind
	Retryable bool
	Msg       string
	// Diagnostics such as a log tail or pod status.
	Diagnostics string
	Err         error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Kind, e.Msg, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Kind, e.Msg)
}

func (e *Error) Unwrap() error { return e.Err }

// ErrScanCancelled is the context cancellation cause used when a user
// cancels a scan. Scanners delete the Kubernetes Job only when
// context.Cause(ctx) is ErrScanCancelled; any other cancellation (controller
// shutdown) leaves the Job running so a restarted controller re-attaches.
var ErrScanCancelled = errors.New("scan cancelled")

// IsRetryable reports whether err is a retryable scan error.
func IsRetryable(err error) bool {
	var se *Error
	if errors.As(err, &se) {
		return se.Retryable
	}
	return false
}

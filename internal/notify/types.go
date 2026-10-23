// Package notify delivers config-only generic webhook notifications.
package notify

import (
	"context"
	"time"
)

// FindingInfo is the template-facing view of a finding.
type FindingInfo struct {
	ID               string   `json:"id"`
	VulnerabilityID  string   `json:"vulnerabilityId"`
	Severity         string   `json:"severity"`
	PkgName          string   `json:"pkgName"`
	InstalledVersion string   `json:"installedVersion"`
	FixedVersion     string   `json:"fixedVersion,omitempty"`
	Title            string   `json:"title,omitempty"`
	PrimaryURL       string   `json:"primaryUrl,omitempty"`
	ImageKey         string   `json:"imageKey"`
	ImageRef         string   `json:"imageRef"`
	Namespaces       []string `json:"namespaces"`
	Workloads        []string `json:"workloads"` // "ns/Kind/name"
}

// ScanInfo is the template-facing view of a scan run.
type ScanInfo struct {
	ID           string    `json:"id"`
	Scope        string    `json:"scope"`
	Namespace    string    `json:"namespace,omitempty"`
	Status       string    `json:"status"`
	Trigger      string    `json:"trigger"`
	TotalImages  int       `json:"totalImages"`
	FailedImages int       `json:"failedImages"`
	Error        string    `json:"error,omitempty"`
	FinishedAt   time.Time `json:"finishedAt"`
}

// Event is one notification-worthy occurrence. Type is one of
// config.EventNewCritical, config.EventResolved, config.EventScanFailed.
type Event struct {
	Type     string        `json:"type"`
	Scan     ScanInfo      `json:"scan"`
	Findings []FindingInfo `json:"findings"`
	// Cluster is an optional display name.
	Cluster string    `json:"cluster,omitempty"`
	Time    time.Time `json:"time"`
}

// Notifier sends events to configured destinations. Implementations must
// deduplicate (per destination, event type, scan and finding set), record
// deliveries in the store, and never block the caller for long: delivery with
// retries may happen asynchronously.
type Notifier interface {
	Notify(ctx context.Context, ev Event) error
}

// Nop discards events.
type Nop struct{}

func (Nop) Notify(context.Context, Event) error { return nil }

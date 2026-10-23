package store

import "time"

// Scan run scopes.
const (
	ScopeCluster   = "cluster"
	ScopeNamespace = "namespace"
)

// Scan run / job statuses.
const (
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	// StatusPartial means the run finished but some images failed to scan.
	StatusPartial   = "partial"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// Scan triggers.
const (
	TriggerSchedule = "schedule"
	TriggerAPI      = "api"
	TriggerMCP      = "mcp"
	TriggerStartup  = "startup"
)

// ScanRun is one full-cluster or namespace scan.
type ScanRun struct {
	ID string `gorm:"primaryKey;size:36" json:"id"`
	// Scope is cluster | namespace.
	Scope     string `gorm:"size:16;not null;index" json:"scope"`
	Namespace string `gorm:"size:253" json:"namespace,omitempty"`
	// Trigger is schedule | api | mcp | startup.
	Trigger     string `gorm:"size:16;not null" json:"trigger"`
	RequestedBy string `gorm:"size:128" json:"requestedBy,omitempty"`
	// Status is pending | running | succeeded | partial | failed | cancelled.
	Status          string     `gorm:"size:16;not null;index" json:"status"`
	TotalImages     int        `json:"totalImages"`
	CompletedImages int        `json:"completedImages"`
	FailedImages    int        `json:"failedImages"`
	NewFindings     int        `json:"newFindings"`
	ResolvedCount   int        `json:"resolvedFindings"`
	Error           string     `gorm:"type:text" json:"error,omitempty"`
	CancelRequested bool       `json:"cancelRequested"`
	CreatedAt       time.Time  `gorm:"index" json:"createdAt"`
	StartedAt       *time.Time `json:"startedAt,omitempty"`
	FinishedAt      *time.Time `json:"finishedAt,omitempty"`
	UpdatedAt       time.Time  `json:"updatedAt"`
}

// Terminal reports whether the run reached a final state.
func (r *ScanRun) Terminal() bool {
	switch r.Status {
	case StatusSucceeded, StatusPartial, StatusFailed, StatusCancelled:
		return true
	}
	return false
}

// ScanJob is the scan of one image within a run.
type ScanJob struct {
	ID        string `gorm:"primaryKey;size:36" json:"id"`
	ScanRunID string `gorm:"size:36;not null;index;uniqueIndex:ux_run_image" json:"scanRunId"`
	ImageKey  string `gorm:"size:512;not null;uniqueIndex:ux_run_image" json:"imageKey"`
	// ImageRef is the reference passed to Trivy (digest-pinned when known).
	ImageRef string `gorm:"size:1024;not null" json:"imageRef"`
	// Status is pending | running | succeeded | failed | cancelled.
	Status      string     `gorm:"size:16;not null;index" json:"status"`
	Attempts    int        `json:"attempts"`
	K8sJobName  string     `gorm:"size:63" json:"k8sJobName,omitempty"`
	Error       string     `gorm:"type:text" json:"error,omitempty"`
	Diagnostics string     `gorm:"type:text" json:"diagnostics,omitempty"`
	VulnCount   int        `json:"vulnerabilityCount"`
	StartedAt   *time.Time `json:"startedAt,omitempty"`
	FinishedAt  *time.Time `json:"finishedAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

// Image is a deduplicated container image identity. Key is
// "<repository>@<digest>" when a digest is known, otherwise the image ref.
type Image struct {
	Key           string     `gorm:"primaryKey;size:512" json:"key"`
	Repository    string     `gorm:"size:512" json:"repository"`
	Digest        string     `gorm:"size:128;index" json:"digest,omitempty"`
	Ref           string     `gorm:"size:1024" json:"ref"`
	OS            string     `gorm:"size:128" json:"os,omitempty"`
	FirstSeenAt   time.Time  `json:"firstSeenAt"`
	LastSeenAt    time.Time  `json:"lastSeenAt"`
	LastScannedAt *time.Time `json:"lastScannedAt,omitempty"`
	// Deployed is false once no active workload references the image.
	Deployed bool `gorm:"index" json:"deployed"`
}

// Workload associates an image with a namespaced owner and container.
type Workload struct {
	ID          uint      `gorm:"primaryKey" json:"-"`
	ImageKey    string    `gorm:"size:512;not null;uniqueIndex:ux_workload" json:"imageKey"`
	Namespace   string    `gorm:"size:253;not null;index;uniqueIndex:ux_workload" json:"namespace"`
	Kind        string    `gorm:"size:64;not null;uniqueIndex:ux_workload" json:"kind"`
	Name        string    `gorm:"size:253;not null;uniqueIndex:ux_workload" json:"name"`
	Container   string    `gorm:"size:253;not null;uniqueIndex:ux_workload" json:"container"`
	Active      bool      `gorm:"index" json:"active"`
	FirstSeenAt time.Time `json:"firstSeenAt"`
	LastSeenAt  time.Time `json:"lastSeenAt"`
}

// Finding statuses.
const (
	FindingOpen     = "open"
	FindingResolved = "resolved"
)

// Finding is one vulnerability in one image. ID is a stable hash of
// image key + vulnerability ID + package name + installed version.
type Finding struct {
	ID               string `gorm:"primaryKey;size:64" json:"id"`
	ImageKey         string `gorm:"size:512;not null;index" json:"imageKey"`
	VulnerabilityID  string `gorm:"size:128;not null;index" json:"vulnerabilityId"`
	PkgName          string `gorm:"size:512;not null" json:"pkgName"`
	PkgPath          string `gorm:"size:1024" json:"pkgPath,omitempty"`
	InstalledVersion string `gorm:"size:256" json:"installedVersion"`
	FixedVersion     string `gorm:"size:512" json:"fixedVersion,omitempty"`
	Severity         string `gorm:"size:16;index" json:"severity"`
	Title            string `gorm:"size:1024" json:"title,omitempty"`
	PrimaryURL       string `gorm:"size:1024" json:"primaryUrl,omitempty"`
	// Status is open | resolved.
	Status      string     `gorm:"size:16;not null;index" json:"status"`
	FirstSeenAt time.Time  `json:"firstSeenAt"`
	LastSeenAt  time.Time  `json:"lastSeenAt"`
	ResolvedAt  *time.Time `json:"resolvedAt,omitempty"`
	// ResolutionReason is fixed | not_deployed when resolved.
	ResolutionReason string     `gorm:"size:32" json:"resolutionReason,omitempty"`
	ReopenedAt       *time.Time `json:"reopenedAt,omitempty"`
	AcknowledgedAt   *time.Time `json:"acknowledgedAt,omitempty"`
	AckBy            string     `gorm:"size:128" json:"acknowledgedBy,omitempty"`
	AckReason        string     `gorm:"type:text" json:"acknowledgeReason,omitempty"`
	// LastScanRunID is the run that last observed this finding.
	LastScanRunID string    `gorm:"size:36" json:"lastScanRunId,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// Resolution reasons.
const (
	ResolutionFixed       = "fixed"
	ResolutionNotDeployed = "not_deployed"
)

// Silence kinds.
const (
	SilenceFinding   = "finding"
	SilenceImage     = "image"
	SilenceNamespace = "namespace"
	// SilenceVulnerability silences a CVE ID everywhere.
	SilenceVulnerability = "vulnerability"
)

// Silence suppresses alerts (not visibility) for matching findings.
type Silence struct {
	ID string `gorm:"primaryKey;size:36" json:"id"`
	// Kind is finding | image | namespace | vulnerability.
	Kind      string     `gorm:"size:16;not null;index" json:"kind"`
	Target    string     `gorm:"size:512;not null;index" json:"target"`
	Reason    string     `gorm:"type:text" json:"reason,omitempty"`
	CreatedBy string     `gorm:"size:128" json:"createdBy,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt *time.Time `gorm:"index" json:"expiresAt,omitempty"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	RevokedBy string     `gorm:"size:128" json:"revokedBy,omitempty"`
}

// ActiveAt reports whether the silence applies at t.
func (s *Silence) ActiveAt(t time.Time) bool {
	if s.RevokedAt != nil {
		return false
	}
	return s.ExpiresAt == nil || s.ExpiresAt.After(t)
}

// Notification delivery statuses.
const (
	DeliveryPending   = "pending"
	DeliveryDelivered = "delivered"
	DeliveryFailed    = "failed"
)

// NotificationDelivery records one webhook delivery; DedupKey prevents
// duplicate notifications for the same event and destination.
type NotificationDelivery struct {
	ID          string `gorm:"primaryKey;size:36" json:"id"`
	Destination string `gorm:"size:128;not null;index" json:"destination"`
	Event       string `gorm:"size:32;not null" json:"event"`
	DedupKey    string `gorm:"size:128;not null;uniqueIndex" json:"dedupKey"`
	ScanRunID   string `gorm:"size:36;index" json:"scanRunId,omitempty"`
	// Status is pending | delivered | failed.
	Status       string     `gorm:"size:16;not null;index" json:"status"`
	Attempts     int        `json:"attempts"`
	ResponseCode int        `json:"responseCode,omitempty"`
	LastError    string     `gorm:"type:text" json:"lastError,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	DeliveredAt  *time.Time `json:"deliveredAt,omitempty"`
	UpdatedAt    time.Time  `json:"updatedAt"`
}

// AllModels lists every persisted model for migrations.
func AllModels() []any {
	return []any{&ScanRun{}, &ScanJob{}, &Image{}, &Workload{}, &Finding{}, &Silence{}, &NotificationDelivery{}}
}

// Package service holds the application operations shared by the REST API
// and MCP server. Every method enforces authorization from the context
// principal (see auth.Require), so transports cannot diverge.
package service

import (
	"context"
	"errors"
	"time"

	"github.com/l4r-s/krivy/internal/store"
)

var (
	// ErrInvalid wraps validation errors (HTTP 400).
	ErrInvalid = errors.New("invalid request")
	// ErrConflict signals a state conflict (HTTP 409).
	ErrConflict = errors.New("conflict")
)

// ScanRequest triggers a scan.
type ScanRequest struct {
	// Scope is "cluster" or "namespace".
	Scope     string `json:"scope"`
	Namespace string `json:"namespace,omitempty"`
}

// ScanStatus is a run plus its per-image jobs.
type ScanStatus struct {
	store.ScanRun
	Jobs []store.ScanJob `json:"jobs,omitempty"`
}

// FindingDetail is a finding with its image and affected workloads.
type FindingDetail struct {
	store.Finding
	Image      *store.Image     `json:"image,omitempty"`
	Workloads  []store.Workload `json:"workloads"`
	Namespaces []string         `json:"namespaces"`
	// Silenced reports whether an active silence currently covers it.
	Silenced   bool     `json:"silenced"`
	SilencedBy []string `json:"silencedBy,omitempty"`
}

// AckRequest acknowledges a finding.
type AckRequest struct {
	Reason string `json:"reason,omitempty"`
}

// SilenceRequest creates a silence.
type SilenceRequest struct {
	// Kind is finding | image | namespace | vulnerability.
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Reason string `json:"reason,omitempty"`
	// ExpiresAt or Duration (e.g. "720h") bound the silence; both empty = no expiry.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Duration  string     `json:"duration,omitempty"`
}

// API is the application surface used by REST and MCP.
//
// Scopes: read for Get/List/Summary, scan for TriggerScan/CancelScan,
// manage for Acknowledge/Unacknowledge/silence mutations.
type API interface {
	TriggerScan(ctx context.Context, req ScanRequest, trigger string) (*store.ScanRun, error)
	GetScan(ctx context.Context, id string) (*ScanStatus, error)
	ListScans(ctx context.Context, f store.ScanRunFilter) ([]store.ScanRun, int64, error)
	CancelScan(ctx context.Context, id string) (*store.ScanRun, error)

	ListFindings(ctx context.Context, f store.FindingFilter) ([]store.Finding, int64, error)
	GetFinding(ctx context.Context, id string) (*FindingDetail, error)
	Acknowledge(ctx context.Context, id string, req AckRequest) (*store.Finding, error)
	Unacknowledge(ctx context.Context, id string) (*store.Finding, error)

	CreateSilence(ctx context.Context, req SilenceRequest) (*store.Silence, error)
	ListSilences(ctx context.Context, includeInactive bool) ([]store.Silence, error)
	RevokeSilence(ctx context.Context, id string) (*store.Silence, error)

	Summary(ctx context.Context) (*store.Summary, error)
}

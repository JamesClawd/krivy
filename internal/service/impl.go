package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/l4r-s/krivy/internal/auth"
	"github.com/l4r-s/krivy/internal/config"
	"github.com/l4r-s/krivy/internal/findings"
	"github.com/l4r-s/krivy/internal/orchestrator"
	"github.com/l4r-s/krivy/internal/store"
)

// Queue is the subset of the orchestrator the service needs.
type Queue interface {
	Enqueue(ctx context.Context, scope, namespace, trigger, actor string) (*store.ScanRun, bool, error)
	Cancel(ctx context.Context, id string) (*store.ScanRun, error)
}

// Service implements API.
type Service struct {
	st  store.Store
	q   Queue
	now func() time.Time
}

var _ API = (*Service)(nil)

// New creates the service.
func New(st store.Store, q Queue) *Service {
	return &Service{st: st, q: q, now: func() time.Time { return time.Now().UTC() }}
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

func (s *Service) TriggerScan(ctx context.Context, req ScanRequest, trigger string) (*store.ScanRun, error) {
	p, err := auth.Require(ctx, config.ScopeScan)
	if err != nil {
		return nil, err
	}
	if req.Scope == "" {
		req.Scope = store.ScopeCluster
		if req.Namespace != "" {
			req.Scope = store.ScopeNamespace
		}
	}
	if req.Scope == store.ScopeNamespace && !validName(req.Namespace) {
		return nil, invalid("namespace must be a valid Kubernetes namespace name")
	}
	run, _, err := s.q.Enqueue(ctx, req.Scope, req.Namespace, trigger, p.Actor())
	if errors.Is(err, orchestrator.ErrInvalidScope) {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	return run, err
}

func (s *Service) GetScan(ctx context.Context, id string) (*ScanStatus, error) {
	if _, err := auth.Require(ctx, config.ScopeRead); err != nil {
		return nil, err
	}
	run, err := s.st.GetScanRun(ctx, id)
	if err != nil {
		return nil, err
	}
	jobs, err := s.st.ListScanJobs(ctx, id)
	if err != nil {
		return nil, err
	}
	return &ScanStatus{ScanRun: *run, Jobs: jobs}, nil
}

func (s *Service) ListScans(ctx context.Context, f store.ScanRunFilter) ([]store.ScanRun, int64, error) {
	if _, err := auth.Require(ctx, config.ScopeRead); err != nil {
		return nil, 0, err
	}
	return s.st.ListScanRuns(ctx, f)
}

func (s *Service) CancelScan(ctx context.Context, id string) (*store.ScanRun, error) {
	if _, err := auth.Require(ctx, config.ScopeScan); err != nil {
		return nil, err
	}
	return s.q.Cancel(ctx, id)
}

func (s *Service) ListFindings(ctx context.Context, f store.FindingFilter) ([]store.Finding, int64, error) {
	if _, err := auth.Require(ctx, config.ScopeRead); err != nil {
		return nil, 0, err
	}
	switch f.Status {
	case "", store.FindingOpen, store.FindingResolved:
	default:
		return nil, 0, invalid("status must be open or resolved")
	}
	return s.st.ListFindings(ctx, f)
}

func (s *Service) GetFinding(ctx context.Context, id string) (*FindingDetail, error) {
	if _, err := auth.Require(ctx, config.ScopeRead); err != nil {
		return nil, err
	}
	f, err := s.st.GetFinding(ctx, id)
	if err != nil {
		return nil, err
	}
	d := &FindingDetail{Finding: *f, Workloads: []store.Workload{}, Namespaces: []string{}}
	if img, err := s.st.GetImage(ctx, f.ImageKey); err == nil {
		d.Image = img
	}
	ws, err := s.st.ListWorkloads(ctx, []string{f.ImageKey}, true)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, w := range ws {
		d.Workloads = append(d.Workloads, w)
		if !seen[w.Namespace] {
			seen[w.Namespace] = true
			d.Namespaces = append(d.Namespaces, w.Namespace)
		}
	}
	sort.Strings(d.Namespaces)
	now := s.now()
	silences, err := s.st.ListSilences(ctx, &now)
	if err != nil {
		return nil, err
	}
	repo := ""
	if d.Image != nil {
		repo = d.Image.Repository
	}
	d.SilencedBy = findings.NewPolicy(silences, now).SilencedBy(f, repo, d.Namespaces)
	d.Silenced = len(d.SilencedBy) > 0
	return d, nil
}

func (s *Service) Acknowledge(ctx context.Context, id string, req AckRequest) (*store.Finding, error) {
	p, err := auth.Require(ctx, config.ScopeManage)
	if err != nil {
		return nil, err
	}
	if len(req.Reason) > 2000 {
		return nil, invalid("reason must be at most 2000 characters")
	}
	var out *store.Finding
	err = s.st.Transaction(ctx, func(tx store.Store) error {
		f, err := tx.GetFinding(ctx, id)
		if err != nil {
			return err
		}
		now := s.now()
		f.AcknowledgedAt = &now
		f.AckBy = p.Actor()
		f.AckReason = req.Reason
		out = f
		return tx.SaveFinding(ctx, f)
	})
	return out, err
}

func (s *Service) Unacknowledge(ctx context.Context, id string) (*store.Finding, error) {
	if _, err := auth.Require(ctx, config.ScopeManage); err != nil {
		return nil, err
	}
	var out *store.Finding
	err := s.st.Transaction(ctx, func(tx store.Store) error {
		f, err := tx.GetFinding(ctx, id)
		if err != nil {
			return err
		}
		f.AcknowledgedAt, f.AckBy, f.AckReason = nil, "", ""
		out = f
		return tx.SaveFinding(ctx, f)
	})
	return out, err
}

func (s *Service) CreateSilence(ctx context.Context, req SilenceRequest) (*store.Silence, error) {
	p, err := auth.Require(ctx, config.ScopeManage)
	if err != nil {
		return nil, err
	}
	req.Target = strings.TrimSpace(req.Target)
	switch req.Kind {
	case store.SilenceFinding, store.SilenceImage, store.SilenceVulnerability:
	case store.SilenceNamespace:
		if !validName(req.Target) {
			return nil, invalid("target must be a valid namespace name")
		}
	default:
		return nil, invalid("kind must be finding, image, namespace or vulnerability")
	}
	if req.Target == "" || len(req.Target) > 512 {
		return nil, invalid("target is required (max 512 characters)")
	}
	if len(req.Reason) > 2000 {
		return nil, invalid("reason must be at most 2000 characters")
	}
	now := s.now()
	expires := req.ExpiresAt
	if req.Duration != "" {
		if expires != nil {
			return nil, invalid("set either expiresAt or duration, not both")
		}
		d, err := time.ParseDuration(req.Duration)
		if err != nil || d <= 0 {
			return nil, invalid("duration must be a positive Go duration such as 720h")
		}
		t := now.Add(d)
		expires = &t
	}
	if expires != nil && !expires.After(now) {
		return nil, invalid("expiry must be in the future")
	}
	if req.Kind == store.SilenceFinding {
		if _, err := s.st.GetFinding(ctx, req.Target); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, invalid("finding %q does not exist", req.Target)
			}
			return nil, err
		}
	}
	sl := &store.Silence{
		ID: uuid.NewString(), Kind: req.Kind, Target: req.Target, Reason: req.Reason,
		CreatedBy: p.Actor(), CreatedAt: now, ExpiresAt: expires,
	}
	if err := s.st.CreateSilence(ctx, sl); err != nil {
		return nil, err
	}
	return sl, nil
}

func (s *Service) ListSilences(ctx context.Context, includeInactive bool) ([]store.Silence, error) {
	if _, err := auth.Require(ctx, config.ScopeRead); err != nil {
		return nil, err
	}
	if includeInactive {
		return s.st.ListSilences(ctx, nil)
	}
	now := s.now()
	return s.st.ListSilences(ctx, &now)
}

func (s *Service) RevokeSilence(ctx context.Context, id string) (*store.Silence, error) {
	p, err := auth.Require(ctx, config.ScopeManage)
	if err != nil {
		return nil, err
	}
	sl, err := s.st.GetSilence(ctx, id)
	if err != nil {
		return nil, err
	}
	if sl.RevokedAt != nil {
		return sl, nil
	}
	now := s.now()
	sl.RevokedAt = &now
	sl.RevokedBy = p.Actor()
	if err := s.st.UpdateSilence(ctx, sl); err != nil {
		return nil, err
	}
	return sl, nil
}

func (s *Service) Summary(ctx context.Context) (*store.Summary, error) {
	if _, err := auth.Require(ctx, config.ScopeRead); err != nil {
		return nil, err
	}
	return s.st.Summary(ctx)
}

// validName checks a DNS-1123 label (Kubernetes namespace name).
func validName(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i, c := range s {
		alnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !alnum && (c != '-' || i == 0 || i == len(s)-1) {
			return false
		}
	}
	return true
}

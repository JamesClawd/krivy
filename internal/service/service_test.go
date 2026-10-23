package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/l4r-s/krivy/internal/auth"
	"github.com/l4r-s/krivy/internal/config"
	"github.com/l4r-s/krivy/internal/orchestrator"
	"github.com/l4r-s/krivy/internal/store"
	"github.com/l4r-s/krivy/internal/store/storetest"
)

type fakeQueue struct {
	mu        sync.Mutex
	enqueued  []string
	cancelled []string
}

func (q *fakeQueue) Enqueue(_ context.Context, scope, ns, trigger, actor string) (*store.ScanRun, bool, error) {
	if scope != store.ScopeCluster && scope != store.ScopeNamespace {
		return nil, false, orchestrator.ErrInvalidScope
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.enqueued = append(q.enqueued, scope+"|"+ns+"|"+trigger+"|"+actor)
	return &store.ScanRun{ID: "run-1", Scope: scope, Namespace: ns, Trigger: trigger, RequestedBy: actor, Status: store.StatusPending}, true, nil
}

func (q *fakeQueue) Cancel(_ context.Context, id string) (*store.ScanRun, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.cancelled = append(q.cancelled, id)
	return &store.ScanRun{ID: id, Status: store.StatusCancelled}, nil
}

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func principal(name string, scopes ...config.Scope) context.Context {
	p := &auth.Principal{Name: name, Scopes: map[config.Scope]bool{}}
	for _, s := range scopes {
		p.Scopes[s] = true
	}
	return auth.WithPrincipal(context.Background(), p)
}

var (
	anon      = context.Background()
	readCtx   = principal("reader", config.ScopeRead)
	scanCtx   = principal("ci", config.ScopeScan)
	manageCtx = principal("admin", config.ScopeManage)
)

type fixture struct {
	svc *Service
	st  *store.GormStore
	q   *fakeQueue
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := storetest.SQLite(t)
	q := &fakeQueue{}
	svc := New(st, q)
	svc.now = func() time.Time { return now }
	ctx := context.Background()
	for _, k := range []string{"img-shared", "img-solo"} {
		if err := st.UpsertImage(ctx, &store.Image{Key: k, Repository: "repo/" + k, Ref: k, Deployed: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SyncWorkloads(ctx, "", []store.Workload{
		{ImageKey: "img-shared", Namespace: "staging", Kind: "Deployment", Name: "api", Container: "app"},
		{ImageKey: "img-shared", Namespace: "prod", Kind: "Deployment", Name: "api", Container: "app"},
		{ImageKey: "img-shared", Namespace: "prod", Kind: "Deployment", Name: "worker", Container: "app"},
		{ImageKey: "img-solo", Namespace: "prod", Kind: "Pod", Name: "solo", Container: "c"},
	}, now); err != nil {
		t.Fatal(err)
	}
	for _, f := range []store.Finding{
		{ID: "f-shared", ImageKey: "img-shared", VulnerabilityID: "CVE-1", PkgName: "p", Severity: "CRITICAL", Status: store.FindingOpen, FirstSeenAt: now},
		{ID: "f-solo", ImageKey: "img-solo", VulnerabilityID: "CVE-2", PkgName: "p", Severity: "HIGH", Status: store.FindingOpen, FirstSeenAt: now},
	} {
		f := f
		if err := st.SaveFinding(ctx, &f); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateScanRun(ctx, &store.ScanRun{ID: "existing", Scope: "cluster", Trigger: "api", Status: store.StatusSucceeded, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, st: st, q: q}
}

func TestAuthorizationMatrix(t *testing.T) {
	fx := newFixture(t)
	s := fx.svc
	ops := []struct {
		name string
		need config.Scope
		call func(ctx context.Context) error
	}{
		{"TriggerScan", config.ScopeScan, func(ctx context.Context) error {
			_, err := s.TriggerScan(ctx, ScanRequest{}, store.TriggerAPI)
			return err
		}},
		{"CancelScan", config.ScopeScan, func(ctx context.Context) error { _, err := s.CancelScan(ctx, "existing"); return err }},
		{"GetScan", config.ScopeRead, func(ctx context.Context) error { _, err := s.GetScan(ctx, "existing"); return err }},
		{"ListScans", config.ScopeRead, func(ctx context.Context) error {
			_, _, err := s.ListScans(ctx, store.ScanRunFilter{})
			return err
		}},
		{"ListFindings", config.ScopeRead, func(ctx context.Context) error {
			_, _, err := s.ListFindings(ctx, store.FindingFilter{})
			return err
		}},
		{"GetFinding", config.ScopeRead, func(ctx context.Context) error { _, err := s.GetFinding(ctx, "f-solo"); return err }},
		{"Acknowledge", config.ScopeManage, func(ctx context.Context) error {
			_, err := s.Acknowledge(ctx, "f-solo", AckRequest{})
			return err
		}},
		{"Unacknowledge", config.ScopeManage, func(ctx context.Context) error { _, err := s.Unacknowledge(ctx, "f-solo"); return err }},
		{"CreateSilence", config.ScopeManage, func(ctx context.Context) error {
			_, err := s.CreateSilence(ctx, SilenceRequest{Kind: store.SilenceVulnerability, Target: "CVE-9"})
			return err
		}},
		{"ListSilences", config.ScopeRead, func(ctx context.Context) error { _, err := s.ListSilences(ctx, true); return err }},
		{"RevokeSilence", config.ScopeManage, func(ctx context.Context) error {
			sl := &store.Silence{ID: "rv-" + time.Now().Format("150405.000000000"), Kind: "vulnerability", Target: "x", CreatedAt: now}
			if err := fx.st.CreateSilence(context.Background(), sl); err != nil {
				return err
			}
			_, err := s.RevokeSilence(ctx, sl.ID)
			return err
		}},
		{"Summary", config.ScopeRead, func(ctx context.Context) error { _, err := s.Summary(ctx); return err }},
	}
	rank := map[config.Scope]int{config.ScopeRead: 1, config.ScopeScan: 2, config.ScopeManage: 3}
	callers := []struct {
		name  string
		ctx   context.Context
		level int
	}{
		{"anonymous", anon, 0},
		{"read", readCtx, 1},
		{"scan", scanCtx, 2},
		{"manage", manageCtx, 3},
	}
	for _, op := range ops {
		for _, c := range callers {
			t.Run(op.name+"/"+c.name, func(t *testing.T) {
				err := op.call(c.ctx)
				switch {
				case c.level == 0:
					if !errors.Is(err, auth.ErrUnauthenticated) {
						t.Fatalf("err = %v, want ErrUnauthenticated", err)
					}
				case c.level < rank[op.need]:
					if !errors.Is(err, auth.ErrForbidden) {
						t.Fatalf("err = %v, want ErrForbidden", err)
					}
				default:
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				}
			})
		}
	}
}

func TestTriggerScan(t *testing.T) {
	for _, tc := range []struct {
		name    string
		req     ScanRequest
		want    string // enqueued record
		invalid bool
	}{
		{"default cluster", ScanRequest{}, "cluster||api|token:ci", false},
		{"namespace inferred", ScanRequest{Namespace: "prod"}, "namespace|prod|api|token:ci", false},
		{"explicit namespace", ScanRequest{Scope: "namespace", Namespace: "kube-system"}, "namespace|kube-system|api|token:ci", false},
		{"namespace missing", ScanRequest{Scope: "namespace"}, "", true},
		{"namespace uppercase", ScanRequest{Namespace: "Prod"}, "", true},
		{"namespace with dot", ScanRequest{Namespace: "a.b"}, "", true},
		{"namespace leading dash", ScanRequest{Namespace: "-a"}, "", true},
		{"namespace trailing dash", ScanRequest{Namespace: "a-"}, "", true},
		{"namespace too long", ScanRequest{Namespace: strings.Repeat("a", 64)}, "", true},
		{"namespace injection", ScanRequest{Namespace: "prod; drop"}, "", true},
		{"bad scope", ScanRequest{Scope: "galaxy"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			run, err := fx.svc.TriggerScan(scanCtx, tc.req, store.TriggerAPI)
			if tc.invalid {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("err = %v, want ErrInvalid", err)
				}
				if len(fx.q.enqueued) > 0 && tc.req.Scope != "galaxy" {
					t.Fatalf("invalid request reached queue: %v", fx.q.enqueued)
				}
				return
			}
			if err != nil || run == nil {
				t.Fatalf("TriggerScan = %v, %v", run, err)
			}
			if len(fx.q.enqueued) != 1 || fx.q.enqueued[0] != tc.want {
				t.Fatalf("enqueued = %v, want %s", fx.q.enqueued, tc.want)
			}
		})
	}
}

func TestCancelAndGetScan(t *testing.T) {
	fx := newFixture(t)
	r, err := fx.svc.CancelScan(scanCtx, "existing")
	if err != nil || r.Status != store.StatusCancelled || fx.q.cancelled[0] != "existing" {
		t.Fatalf("CancelScan = %+v, %v", r, err)
	}
	if err := fx.st.CreateScanJobs(context.Background(), []store.ScanJob{{ID: "j", ScanRunID: "existing", ImageKey: "img-solo", ImageRef: "img-solo", Status: "succeeded"}}); err != nil {
		t.Fatal(err)
	}
	st, err := fx.svc.GetScan(readCtx, "existing")
	if err != nil || st.ID != "existing" || len(st.Jobs) != 1 {
		t.Fatalf("GetScan = %+v, %v", st, err)
	}
	if _, err := fx.svc.GetScan(readCtx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetScan missing: %v", err)
	}
}

func TestListFindingsValidation(t *testing.T) {
	fx := newFixture(t)
	if _, _, err := fx.svc.ListFindings(readCtx, store.FindingFilter{Status: "closed"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad status: %v", err)
	}
	out, total, err := fx.svc.ListFindings(readCtx, store.FindingFilter{Status: store.FindingOpen, Namespace: "staging"})
	if err != nil || total != 1 || out[0].ID != "f-shared" {
		t.Fatalf("ListFindings = %+v, %d, %v", out, total, err)
	}
}

func TestAckRoundTrip(t *testing.T) {
	fx := newFixture(t)
	f, err := fx.svc.Acknowledge(manageCtx, "f-solo", AckRequest{Reason: "accepted risk"})
	if err != nil {
		t.Fatal(err)
	}
	if f.AckBy != "token:admin" || f.AckReason != "accepted risk" || f.AcknowledgedAt == nil || !f.AcknowledgedAt.Equal(now) {
		t.Fatalf("ack = %+v", f)
	}
	stored, _ := fx.st.GetFinding(context.Background(), "f-solo")
	if stored.AckBy != "token:admin" || stored.AcknowledgedAt == nil {
		t.Fatalf("ack not persisted: %+v", stored)
	}
	f, err = fx.svc.Unacknowledge(manageCtx, "f-solo")
	if err != nil || f.AcknowledgedAt != nil || f.AckBy != "" || f.AckReason != "" {
		t.Fatalf("unack = %+v, %v", f, err)
	}
	stored, _ = fx.st.GetFinding(context.Background(), "f-solo")
	if stored.AcknowledgedAt != nil || stored.AckBy != "" {
		t.Fatalf("unack not persisted: %+v", stored)
	}
	if _, err := fx.svc.Acknowledge(manageCtx, "missing", AckRequest{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ack missing: %v", err)
	}
	if _, err := fx.svc.Unacknowledge(manageCtx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unack missing: %v", err)
	}
	if _, err := fx.svc.Acknowledge(manageCtx, "f-solo", AckRequest{Reason: strings.Repeat("x", 2001)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("long reason: %v", err)
	}
}

func TestCreateSilenceValidation(t *testing.T) {
	past := now.Add(-time.Minute)
	future := now.Add(time.Hour)
	for _, tc := range []struct {
		name        string
		req         SilenceRequest
		wantErr     error
		wantExpires *time.Time
	}{
		{"vulnerability no expiry", SilenceRequest{Kind: "vulnerability", Target: "CVE-1"}, nil, nil},
		{"finding exists", SilenceRequest{Kind: "finding", Target: "f-solo"}, nil, nil},
		{"image trimmed", SilenceRequest{Kind: "image", Target: "  repo/img-solo  "}, nil, nil},
		{"namespace", SilenceRequest{Kind: "namespace", Target: "prod"}, nil, nil},
		{"duration", SilenceRequest{Kind: "vulnerability", Target: "CVE-1", Duration: "720h"}, nil, ptr(now.Add(720 * time.Hour))},
		{"expiresAt", SilenceRequest{Kind: "vulnerability", Target: "CVE-1", ExpiresAt: &future}, nil, &future},
		{"bad kind", SilenceRequest{Kind: "cluster", Target: "x"}, ErrInvalid, nil},
		{"empty kind", SilenceRequest{Target: "x"}, ErrInvalid, nil},
		{"empty target", SilenceRequest{Kind: "image", Target: "   "}, ErrInvalid, nil},
		{"target too long", SilenceRequest{Kind: "image", Target: strings.Repeat("a", 513)}, ErrInvalid, nil},
		{"bad namespace", SilenceRequest{Kind: "namespace", Target: "Not_A_Namespace"}, ErrInvalid, nil},
		{"reason too long", SilenceRequest{Kind: "image", Target: "x", Reason: strings.Repeat("r", 2001)}, ErrInvalid, nil},
		{"duration and expiresAt", SilenceRequest{Kind: "image", Target: "x", Duration: "1h", ExpiresAt: &future}, ErrInvalid, nil},
		{"bad duration", SilenceRequest{Kind: "image", Target: "x", Duration: "forever"}, ErrInvalid, nil},
		{"negative duration", SilenceRequest{Kind: "image", Target: "x", Duration: "-1h"}, ErrInvalid, nil},
		{"past expiry", SilenceRequest{Kind: "image", Target: "x", ExpiresAt: &past}, ErrInvalid, nil},
		{"expiry now", SilenceRequest{Kind: "image", Target: "x", ExpiresAt: &now}, ErrInvalid, nil},
		{"nonexistent finding", SilenceRequest{Kind: "finding", Target: "nope"}, ErrInvalid, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			sl, err := fx.svc.CreateSilence(manageCtx, tc.req)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if all, _ := fx.st.ListSilences(context.Background(), nil); len(all) != 0 {
					t.Fatalf("invalid silence persisted: %+v", all)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if sl.CreatedBy != "token:admin" || sl.Target != strings.TrimSpace(tc.req.Target) || sl.ID == "" {
				t.Fatalf("silence = %+v", sl)
			}
			if (sl.ExpiresAt == nil) != (tc.wantExpires == nil) || (sl.ExpiresAt != nil && !sl.ExpiresAt.Equal(*tc.wantExpires)) {
				t.Fatalf("ExpiresAt = %v, want %v", sl.ExpiresAt, tc.wantExpires)
			}
			if _, err := fx.st.GetSilence(context.Background(), sl.ID); err != nil {
				t.Fatalf("not persisted: %v", err)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestSilenceListAndRevoke(t *testing.T) {
	fx := newFixture(t)
	sl, err := fx.svc.CreateSilence(manageCtx, SilenceRequest{Kind: "vulnerability", Target: "CVE-1"})
	if err != nil {
		t.Fatal(err)
	}
	expired := now.Add(-time.Hour)
	if err := fx.st.CreateSilence(context.Background(), &store.Silence{ID: "old", Kind: "image", Target: "x", CreatedAt: expired, ExpiresAt: &expired}); err != nil {
		t.Fatal(err)
	}
	active, _ := fx.svc.ListSilences(readCtx, false)
	all, _ := fx.svc.ListSilences(readCtx, true)
	if len(active) != 1 || len(all) != 2 {
		t.Fatalf("active=%d all=%d", len(active), len(all))
	}
	r1, err := fx.svc.RevokeSilence(manageCtx, sl.ID)
	if err != nil || r1.RevokedAt == nil || r1.RevokedBy != "token:admin" {
		t.Fatalf("revoke = %+v, %v", r1, err)
	}
	// Idempotent: second revoke by someone else keeps the original record.
	other := principal("other", config.ScopeManage)
	fx.svc.now = func() time.Time { return now.Add(time.Hour) }
	r2, err := fx.svc.RevokeSilence(other, sl.ID)
	if err != nil || r2.RevokedBy != "token:admin" || !r2.RevokedAt.Equal(*r1.RevokedAt) {
		t.Fatalf("second revoke = %+v, %v", r2, err)
	}
	if active, _ := fx.svc.ListSilences(readCtx, false); len(active) != 0 {
		t.Fatalf("revoked silence still active: %+v", active)
	}
	if _, err := fx.svc.RevokeSilence(manageCtx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoke missing: %v", err)
	}
}

func TestGetFindingDetail(t *testing.T) {
	fx := newFixture(t)
	d, err := fx.svc.GetFinding(readCtx, "f-shared")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.Namespaces, ",") != "prod,staging" || len(d.Workloads) != 3 || d.Image == nil || d.Image.Repository != "repo/img-shared" {
		t.Fatalf("detail = %+v", d)
	}
	if d.Silenced || len(d.SilencedBy) != 0 {
		t.Fatalf("unexpectedly silenced: %+v", d.SilencedBy)
	}

	// Silencing only one namespace of a shared image does not silence it.
	if _, err := fx.svc.CreateSilence(manageCtx, SilenceRequest{Kind: "namespace", Target: "staging"}); err != nil {
		t.Fatal(err)
	}
	d, _ = fx.svc.GetFinding(readCtx, "f-shared")
	if d.Silenced {
		t.Fatal("partially silenced shared image reported as silenced")
	}
	ns2, err := fx.svc.CreateSilence(manageCtx, SilenceRequest{Kind: "namespace", Target: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	d, _ = fx.svc.GetFinding(readCtx, "f-shared")
	if !d.Silenced || len(d.SilencedBy) != 2 {
		t.Fatalf("fully silenced: %+v", d.SilencedBy)
	}
	if _, err := fx.svc.RevokeSilence(manageCtx, ns2.ID); err != nil {
		t.Fatal(err)
	}
	// Repository-wide image silence.
	img, err := fx.svc.CreateSilence(manageCtx, SilenceRequest{Kind: "image", Target: "repo/img-shared", Duration: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	d, _ = fx.svc.GetFinding(readCtx, "f-shared")
	if !d.Silenced || strings.Join(d.SilencedBy, ",") != img.ID {
		t.Fatalf("image silence: %+v", d.SilencedBy)
	}
	// Once expired it no longer applies.
	fx.svc.now = func() time.Time { return now.Add(2 * time.Hour) }
	d, _ = fx.svc.GetFinding(readCtx, "f-shared")
	if d.Silenced {
		t.Fatal("expired silence still applied")
	}

	// Finding whose image has no active workloads: empty (non-nil) slices.
	if err := fx.st.SyncWorkloads(context.Background(), "prod", nil, now); err != nil {
		t.Fatal(err)
	}
	d, _ = fx.svc.GetFinding(readCtx, "f-solo")
	if d.Namespaces == nil || d.Workloads == nil || len(d.Namespaces) != 0 {
		t.Fatalf("undeployed detail = %+v", d)
	}
	if _, err := fx.svc.GetFinding(readCtx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing finding: %v", err)
	}
}

func TestSummary(t *testing.T) {
	fx := newFixture(t)
	s, err := fx.svc.Summary(readCtx)
	if err != nil || s.OpenFindings != 2 || s.OpenByNamespace["prod"] != 2 || s.OpenByNamespace["staging"] != 1 {
		t.Fatalf("summary = %+v, %v", s, err)
	}
}

func TestValidName(t *testing.T) {
	for in, want := range map[string]bool{
		"a": true, "prod": true, "kube-system": true, "a1-b2": true, strings.Repeat("a", 63): true,
		"": false, "-a": false, "a-": false, "A": false, "a_b": false, "a.b": false, strings.Repeat("a", 64): false, "ä": false,
	} {
		if got := validName(in); got != want {
			t.Errorf("validName(%q) = %v", in, got)
		}
	}
}

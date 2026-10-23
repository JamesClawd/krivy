package orchestrator_test

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/l4r-s/krivy/internal/config"
	"github.com/l4r-s/krivy/internal/discovery"
	"github.com/l4r-s/krivy/internal/notify"
	"github.com/l4r-s/krivy/internal/orchestrator"
	"github.com/l4r-s/krivy/internal/scanner"
	"github.com/l4r-s/krivy/internal/store"
	"github.com/l4r-s/krivy/internal/store/storetest"
)

// ---- fakes ----

type fakeDisc struct {
	mu      sync.Mutex
	images  []discovery.Image
	err     error
	block   bool
	calls   []string
	started chan string
}

func (d *fakeDisc) set(images ...discovery.Image) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.images = images
}

func (d *fakeDisc) setErr(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.err = err
}

func (d *fakeDisc) Discover(ctx context.Context, ns string) (*discovery.Result, error) {
	d.mu.Lock()
	d.calls = append(d.calls, ns)
	block, err := d.block, d.err
	var out []discovery.Image
	for _, img := range d.images {
		cp := img
		cp.Workloads = nil
		for _, w := range img.Workloads {
			if ns == "" || w.Namespace == ns {
				cp.Workloads = append(cp.Workloads, w)
			}
		}
		if len(cp.Workloads) > 0 {
			out = append(out, cp)
		}
	}
	d.mu.Unlock()
	if d.started != nil {
		select {
		case d.started <- ns:
		default:
		}
	}
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return &discovery.Result{Images: out, Warnings: []string{"test warning"}}, nil
}

func (d *fakeDisc) Calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

// fakeScanner implements scanner.Scanner with per-ref vulnerabilities,
// queued errors, blocking and in-flight tracking.
type fakeScanner struct {
	mu          sync.Mutex
	vulns       map[string][]scanner.Vulnerability
	errs        map[string][]error // consumed one per call; nil = success
	block       map[string]bool    // block until ctx is cancelled
	delay       time.Duration
	calls       []scanner.Target
	inflight    int
	maxInflight int
	started     chan scanner.Target
}

func newFakeScanner() *fakeScanner {
	return &fakeScanner{
		vulns: map[string][]scanner.Vulnerability{}, errs: map[string][]error{},
		block: map[string]bool{}, started: make(chan scanner.Target, 256),
	}
}

var _ scanner.Scanner = (*fakeScanner)(nil)

func (f *fakeScanner) setVulns(ref string, v ...scanner.Vulnerability) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vulns[ref] = v
}

func (f *fakeScanner) queueErrs(ref string, errs ...error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[ref] = append(f.errs[ref], errs...)
}

func (f *fakeScanner) setBlock(ref string, b bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.block[ref] = b
}

func (f *fakeScanner) Scan(ctx context.Context, t scanner.Target) (*scanner.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, t)
	f.inflight++
	if f.inflight > f.maxInflight {
		f.maxInflight = f.inflight
	}
	var err error
	if q := f.errs[t.ImageRef]; len(q) > 0 {
		err, f.errs[t.ImageRef] = q[0], q[1:]
	}
	block, delay := f.block[t.ImageRef], f.delay
	vulns := append([]scanner.Vulnerability{}, f.vulns[t.ImageRef]...)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inflight--
		f.mu.Unlock()
	}()
	select {
	case f.started <- t:
	default:
	}
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return &scanner.Result{ImageRef: t.ImageRef, JobName: "job-" + t.ScanJobID, OS: "alpine 3.20", Vulnerabilities: vulns}, nil
}

func (f *fakeScanner) Calls() []scanner.Target {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]scanner.Target(nil), f.calls...)
}

func (f *fakeScanner) MaxInflight() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxInflight
}

type recNotifier struct {
	mu     sync.Mutex
	events []notify.Event
}

func (n *recNotifier) Notify(_ context.Context, ev notify.Event) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, ev)
	return nil
}

func (n *recNotifier) of(typ string) []notify.Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []notify.Event
	for _, e := range n.events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func (n *recNotifier) all() []notify.Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]notify.Event(nil), n.events...)
}

// ---- harness ----

// syncStore lets tests wait until the orchestrator is fully done with a run:
// finish() persists the terminal status before emitting notifications, and
// the orchestrator only calls ActiveScanRuns again once emit has returned.
type syncStore struct {
	store.Store
	mu         sync.Mutex
	listCalls  int
	terminalAt map[string]int
}

func (s *syncStore) ActiveScanRuns(ctx context.Context) ([]store.ScanRun, error) {
	s.mu.Lock()
	s.listCalls++
	s.mu.Unlock()
	return s.Store.ActiveScanRuns(ctx)
}

func (s *syncStore) UpdateScanRun(ctx context.Context, r *store.ScanRun) error {
	err := s.Store.UpdateScanRun(ctx, r)
	if err == nil && r.Terminal() {
		s.mu.Lock()
		s.terminalAt[r.ID] = s.listCalls
		s.mu.Unlock()
	}
	return err
}

func (s *syncStore) settled(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.terminalAt[id]
	return ok && s.listCalls > at
}

var logger = slog.New(slog.DiscardHandler)

type harness struct {
	t     *testing.T
	st    *store.GormStore
	ss    *syncStore
	disc  *fakeDisc
	sc    *fakeScanner
	notif *recNotifier
	opts  orchestrator.Options
	o     *orchestrator.Orchestrator

	cancel context.CancelFunc
	done   chan error
}

func newHarness(t *testing.T, opts orchestrator.Options) *harness {
	t.Helper()
	if opts.RetryBackoff == 0 {
		opts.RetryBackoff = time.Millisecond
	}
	h := &harness{t: t, st: storetest.SQLite(t), disc: &fakeDisc{started: make(chan string, 16)}, sc: newFakeScanner(), notif: &recNotifier{}, opts: opts}
	h.ss = &syncStore{Store: h.st, terminalAt: map[string]int{}}
	h.o = orchestrator.New(h.ss, h.disc, h.sc, h.notif, opts, logger)
	return h
}

// start runs the orchestrator loop in the background.
func (h *harness) start() {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.done = cancel, make(chan error, 1)
	go func() { h.done <- h.o.Run(ctx) }()
	h.t.Cleanup(h.stop)
}

// stop cancels Run and waits for it to return.
func (h *harness) stop() {
	if h.cancel == nil {
		return
	}
	h.cancel()
	select {
	case err := <-h.done:
		if err != nil {
			h.t.Errorf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		h.t.Error("Run did not stop")
	}
	h.cancel = nil
}

// restart simulates a controller restart with a fresh orchestrator on the
// same store.
func (h *harness) restart() {
	h.t.Helper()
	h.stop()
	h.o = orchestrator.New(h.ss, h.disc, h.sc, h.notif, h.opts, logger)
	h.start()
}

func (h *harness) enqueue(scope, ns string) *store.ScanRun {
	h.t.Helper()
	run, created, err := h.o.Enqueue(context.Background(), scope, ns, store.TriggerAPI, "token:test")
	if err != nil {
		h.t.Fatalf("enqueue: %v", err)
	}
	if !created {
		h.t.Fatalf("enqueue %s/%s deduplicated unexpectedly", scope, ns)
	}
	return run
}

func (h *harness) scan(scope, ns string) *store.ScanRun {
	h.t.Helper()
	return h.wait(h.enqueue(scope, ns).ID)
}

func (h *harness) wait(id string) *store.ScanRun {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r, err := h.st.GetScanRun(context.Background(), id)
		if err != nil {
			h.t.Fatal(err)
		}
		// Terminal and the orchestrator has moved on (notifications sent).
		if r.Terminal() && h.ss.settled(id) {
			return r
		}
		time.Sleep(2 * time.Millisecond)
	}
	h.t.Fatalf("run %s did not finish", id)
	return nil
}

func (h *harness) jobs(runID string) []store.ScanJob {
	h.t.Helper()
	js, err := h.st.ListScanJobs(context.Background(), runID)
	if err != nil {
		h.t.Fatal(err)
	}
	return js
}

func (h *harness) findings(f store.FindingFilter) []store.Finding {
	h.t.Helper()
	out, _, err := h.st.ListFindings(context.Background(), f)
	if err != nil {
		h.t.Fatal(err)
	}
	return out
}

func waitFor[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for signal")
	}
	var zero T
	return zero
}

func img(name string, workloads ...string) discovery.Image {
	key := "registry.example/" + name + "@sha256:" + name
	im := discovery.Image{Key: key, Repository: "registry.example/" + name, Digest: "sha256:" + name, Ref: key}
	for _, w := range workloads {
		ns, n, _ := strings.Cut(w, "/")
		im.Workloads = append(im.Workloads, discovery.WorkloadRef{Namespace: ns, Kind: "Deployment", Name: n, Container: "app", ContainerType: "container"})
	}
	return im
}

func crit(id string) scanner.Vulnerability {
	return scanner.Vulnerability{VulnerabilityID: id, PkgName: "pkg-" + id, InstalledVersion: "1.0", Severity: "CRITICAL", FixedVersion: "1.1"}
}

func high(id string) scanner.Vulnerability {
	return scanner.Vulnerability{VulnerabilityID: id, PkgName: "pkg-" + id, InstalledVersion: "1.0", Severity: "HIGH"}
}

func vulnIDs(infos []notify.FindingInfo) string {
	var ids []string
	for _, f := range infos {
		ids = append(ids, f.VulnerabilityID)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

var retryable = &scanner.Error{Kind: scanner.KindTimeout, Retryable: true, Msg: "deadline exceeded"}
var fatal = &scanner.Error{Kind: scanner.KindImagePull, Retryable: false, Msg: "manifest unknown", Diagnostics: "pull log"}

// ---- tests ----

func TestClusterScanLifecycle(t *testing.T) {
	h := newHarness(t, orchestrator.Options{MaxConcurrentJobs: 2, Cluster: "test"})
	a, b := img("a", "prod/api", "staging/api"), img("b", "prod/web")
	h.disc.set(a, b)
	h.sc.setVulns(a.Ref, crit("CVE-1"), high("CVE-2"))
	h.start()

	// 1. First scan creates findings and alerts once for the CRITICAL one.
	r := h.scan(store.ScopeCluster, "")
	if r.Status != store.StatusSucceeded || r.TotalImages != 2 || r.CompletedImages != 2 || r.NewFindings != 2 || r.StartedAt == nil || r.FinishedAt == nil {
		t.Fatalf("run = %+v", r)
	}
	if got := len(h.findings(store.FindingFilter{Status: store.FindingOpen})); got != 2 {
		t.Fatalf("open findings = %d", got)
	}
	ev := h.notif.of(config.EventNewCritical)
	if len(ev) != 1 || vulnIDs(ev[0].Findings) != "CVE-1" {
		t.Fatalf("new_critical events = %+v", ev)
	}
	fi := ev[0].Findings[0]
	if strings.Join(fi.Namespaces, ",") != "prod,staging" || len(fi.Workloads) != 2 || fi.ImageRef != a.Ref || ev[0].Cluster != "test" || ev[0].Scan.ID != r.ID {
		t.Fatalf("finding info = %+v / %+v", fi, ev[0])
	}
	for _, j := range h.jobs(r.ID) {
		if j.Status != store.StatusSucceeded || j.Attempts != 1 || j.K8sJobName == "" {
			t.Fatalf("job = %+v", j)
		}
	}
	im, _ := h.st.GetImage(context.Background(), a.Key)
	if im.LastScannedAt == nil || im.OS != "alpine 3.20" || !im.Deployed {
		t.Fatalf("image = %+v", im)
	}

	// 2. Identical scan: nothing new, nothing resolved.
	r = h.scan(store.ScopeCluster, "")
	if r.Status != store.StatusSucceeded || r.NewFindings != 0 || r.ResolvedCount != 0 {
		t.Fatalf("second run = %+v", r)
	}
	if n := len(h.notif.all()); n != 1 {
		t.Fatalf("second scan emitted events: %+v", h.notif.all())
	}

	// 3. Image a is fixed: both findings resolve, one resolved event.
	h.sc.setVulns(a.Ref)
	r = h.scan(store.ScopeCluster, "")
	if r.Status != store.StatusSucceeded || r.ResolvedCount != 2 {
		t.Fatalf("third run = %+v", r)
	}
	res := h.notif.of(config.EventResolved)
	if len(res) != 1 || vulnIDs(res[0].Findings) != "CVE-1,CVE-2" {
		t.Fatalf("resolved events = %+v", res)
	}
	for _, f := range h.findings(store.FindingFilter{}) {
		if f.Status != store.FindingResolved || f.ResolutionReason != store.ResolutionFixed {
			t.Fatalf("finding = %+v", f)
		}
	}
	if n := len(h.notif.of(config.EventScanFailed)); n != 0 {
		t.Fatalf("unexpected scan_failed events: %d", n)
	}
}

func TestImageRemovedFromClusterResolvesNotDeployed(t *testing.T) {
	h := newHarness(t, orchestrator.Options{})
	a, b := img("a", "prod/api"), img("b", "prod/web")
	h.disc.set(a, b)
	h.sc.setVulns(a.Ref, crit("CVE-1"))
	h.start()
	h.scan(store.ScopeCluster, "")
	h.disc.set(b)
	r := h.scan(store.ScopeCluster, "")
	if r.ResolvedCount != 1 {
		t.Fatalf("run = %+v", r)
	}
	f := h.findings(store.FindingFilter{})
	if len(f) != 1 || f[0].ResolutionReason != store.ResolutionNotDeployed {
		t.Fatalf("findings = %+v", f)
	}
	if ev := h.notif.of(config.EventResolved); len(ev) != 1 {
		t.Fatalf("resolved events = %+v", ev)
	}
}

func TestNamespaceScanIsolation(t *testing.T) {
	h := newHarness(t, orchestrator.Options{})
	shared, prodOnly, stagingOnly := img("shared", "prod/api", "staging/api"), img("prodonly", "prod/db"), img("stagingonly", "staging/job")
	h.disc.set(shared, prodOnly, stagingOnly)
	for _, im := range []discovery.Image{shared, prodOnly, stagingOnly} {
		h.sc.setVulns(im.Ref, crit("CVE-"+im.Digest))
	}
	h.start()
	h.scan(store.ScopeCluster, "")
	if n := len(h.findings(store.FindingFilter{Status: store.FindingOpen})); n != 3 {
		t.Fatalf("open = %d", n)
	}

	// Production's image is "fixed", but a staging scan must not look at it.
	h.sc.setVulns(prodOnly.Ref)
	// Staging loses everything except the shared image.
	h.disc.set(img("shared", "prod/api", "staging/api"), prodOnly)
	callsBefore := len(h.sc.Calls())
	r := h.scan(store.ScopeNamespace, "staging")
	if r.Status != store.StatusSucceeded || r.TotalImages != 1 {
		t.Fatalf("staging run = %+v", r)
	}
	if got := h.disc.Calls(); got[len(got)-1] != "staging" {
		t.Fatalf("discovery calls = %v", got)
	}
	calls := h.sc.Calls()[callsBefore:]
	if len(calls) != 1 || calls[0].ImageRef != shared.Ref {
		t.Fatalf("staging scan scanned %+v", calls)
	}
	open := map[string]bool{}
	for _, f := range h.findings(store.FindingFilter{Status: store.FindingOpen}) {
		open[f.ImageKey] = true
	}
	if !open[shared.Key] || !open[prodOnly.Key] || open[stagingOnly.Key] {
		t.Fatalf("open findings by image = %v", open)
	}
	ws, _ := h.st.ListWorkloads(context.Background(), nil, true)
	var active []string
	for _, w := range ws {
		active = append(active, w.Namespace+"/"+w.Name)
	}
	if strings.Join(active, ",") != "prod/api,prod/db,staging/api" {
		t.Fatalf("active workloads = %v", active)
	}
	prodFindings := h.findings(store.FindingFilter{Namespace: "prod", Status: store.FindingOpen})
	if len(prodFindings) != 2 {
		t.Fatalf("prod findings = %+v", prodFindings)
	}
}

func TestEnqueueDedupeAndValidation(t *testing.T) {
	h := newHarness(t, orchestrator.Options{WatchNamespace: ""})
	ctx := context.Background()
	// Run is not started, so everything stays pending.
	cluster := h.enqueue(store.ScopeCluster, "ignored-namespace")
	if cluster.Namespace != "" || cluster.Status != store.StatusPending || cluster.RequestedBy != "token:test" {
		t.Fatalf("cluster run = %+v", cluster)
	}
	for _, tc := range []struct {
		name, scope, ns string
		wantID          string
	}{
		{"identical cluster", store.ScopeCluster, "", cluster.ID},
		{"namespace covered by cluster", store.ScopeNamespace, "prod", cluster.ID},
	} {
		r, created, err := h.o.Enqueue(ctx, tc.scope, tc.ns, store.TriggerMCP, "x")
		if err != nil || created || r.ID != tc.wantID {
			t.Fatalf("%s: run=%v created=%v err=%v", tc.name, r, created, err)
		}
	}
	// Cancel-requested runs are ignored for dedupe.
	if _, err := h.o.Cancel(ctx, cluster.ID); err != nil {
		t.Fatal(err)
	}
	prod := h.enqueue(store.ScopeNamespace, "prod")
	r, created, _ := h.o.Enqueue(ctx, store.ScopeNamespace, "prod", store.TriggerAPI, "x")
	if created || r.ID != prod.ID {
		t.Fatal("identical namespace run not deduplicated")
	}
	staging := h.enqueue(store.ScopeNamespace, "staging")
	if staging.ID == prod.ID {
		t.Fatal("different namespace deduplicated")
	}
	// A cluster request is not covered by namespace runs.
	h.enqueue(store.ScopeCluster, "")

	for _, tc := range []struct{ scope, ns string }{
		{"galaxy", ""},
		{store.ScopeNamespace, ""},
		{"", "prod"},
	} {
		if _, _, err := h.o.Enqueue(ctx, tc.scope, tc.ns, "api", "x"); !errors.Is(err, orchestrator.ErrInvalidScope) {
			t.Errorf("Enqueue(%q,%q) err = %v", tc.scope, tc.ns, err)
		}
	}

	w := newHarness(t, orchestrator.Options{WatchNamespace: "prod"})
	if _, _, err := w.o.Enqueue(ctx, store.ScopeNamespace, "staging", "api", "x"); !errors.Is(err, orchestrator.ErrInvalidScope) {
		t.Fatalf("namespace outside watch: %v", err)
	}
	w.disc.set(img("a", "prod/x", "staging/y"))
	w.start()
	w.scan(store.ScopeNamespace, "prod")
	r2 := w.scan(store.ScopeCluster, "")
	if calls := w.disc.Calls(); strings.Join(calls, ",") != "prod,prod" || r2.Status != store.StatusSucceeded {
		t.Fatalf("watch namespace discovery calls = %v", calls)
	}
}

func TestRetryThenSuccess(t *testing.T) {
	h := newHarness(t, orchestrator.Options{MaxAttempts: 3})
	a := img("a", "prod/api")
	h.disc.set(a)
	h.sc.queueErrs(a.Ref, retryable, retryable)
	h.sc.setVulns(a.Ref, crit("CVE-1"))
	h.start()
	r := h.scan(store.ScopeCluster, "")
	if r.Status != store.StatusSucceeded {
		t.Fatalf("run = %+v", r)
	}
	var attempts []int
	for _, c := range h.sc.Calls() {
		attempts = append(attempts, c.Attempt)
	}
	if len(attempts) != 3 || attempts[0] != 1 || attempts[1] != 2 || attempts[2] != 3 {
		t.Fatalf("attempts = %v", attempts)
	}
	j := h.jobs(r.ID)[0]
	if j.Attempts != 3 || j.Status != store.StatusSucceeded || j.Error != "" {
		t.Fatalf("job = %+v", j)
	}
	if len(h.notif.of(config.EventNewCritical)) != 1 || len(h.notif.of(config.EventScanFailed)) != 0 {
		t.Fatalf("events = %+v", h.notif.all())
	}
}

func TestFailures(t *testing.T) {
	for _, tc := range []struct {
		name         string
		setup        func(h *harness, a, b discovery.Image)
		wantStatus   string
		wantCalls    int
		wantErrPart  string
		wantFailedBy map[string]int // image ref -> attempts of failed job
	}{
		{
			name:        "non-retryable failure is partial",
			setup:       func(h *harness, a, b discovery.Image) { h.sc.queueErrs(a.Ref, fatal) },
			wantStatus:  store.StatusPartial,
			wantCalls:   2,
			wantErrPart: "1 of 2 image scans failed",
		},
		{
			name:        "retryable exhausted is partial",
			setup:       func(h *harness, a, b discovery.Image) { h.sc.queueErrs(a.Ref, retryable, retryable, retryable) },
			wantStatus:  store.StatusPartial,
			wantCalls:   3, // a twice (MaxAttempts 2), b once
			wantErrPart: "1 of 2 image scans failed",
		},
		{
			name:        "plain error is not retried",
			setup:       func(h *harness, a, b discovery.Image) { h.sc.queueErrs(a.Ref, errors.New("boom")) },
			wantStatus:  store.StatusPartial,
			wantCalls:   2,
			wantErrPart: "1 of 2",
		},
		{
			name: "all failed",
			setup: func(h *harness, a, b discovery.Image) {
				h.sc.queueErrs(a.Ref, fatal)
				h.sc.queueErrs(b.Ref, fatal)
			},
			wantStatus:  store.StatusFailed,
			wantCalls:   2,
			wantErrPart: "all 2 image scans failed",
		},
		{
			name:        "discovery error",
			setup:       func(h *harness, a, b discovery.Image) { h.disc.setErr(errors.New("apiserver down")) },
			wantStatus:  store.StatusFailed,
			wantCalls:   0,
			wantErrPart: "discovery: apiserver down",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, orchestrator.Options{MaxAttempts: 2})
			a, b := img("a", "prod/a"), img("b", "prod/b")
			h.disc.set(a, b)
			h.sc.setVulns(b.Ref, crit("CVE-B"))
			tc.setup(h, a, b)
			h.start()
			r := h.scan(store.ScopeCluster, "")
			if r.Status != tc.wantStatus || !strings.Contains(r.Error, tc.wantErrPart) {
				t.Fatalf("run status=%s error=%q", r.Status, r.Error)
			}
			if n := len(h.sc.Calls()); n != tc.wantCalls {
				t.Fatalf("scanner calls = %d, want %d", n, tc.wantCalls)
			}
			ev := h.notif.of(config.EventScanFailed)
			if len(ev) != 1 || ev[0].Scan.Status != tc.wantStatus || !strings.Contains(ev[0].Scan.Error, tc.wantErrPart) {
				t.Fatalf("scan_failed events = %+v", ev)
			}
			if tc.wantCalls > 0 && !strings.Contains(ev[0].Scan.Error, a.Ref) {
				t.Fatalf("scan_failed error should list failed ref: %q", ev[0].Scan.Error)
			}
			for _, j := range h.jobs(r.ID) {
				if j.ImageKey == a.Key {
					if j.Status != store.StatusFailed || j.Error == "" || j.FinishedAt == nil {
						t.Fatalf("failed job = %+v", j)
					}
				}
			}
			if tc.wantStatus == store.StatusPartial {
				// Successful images still produce findings and alerts.
				if ev := h.notif.of(config.EventNewCritical); len(ev) != 1 || vulnIDs(ev[0].Findings) != "CVE-B" {
					t.Fatalf("new_critical = %+v", ev)
				}
				if r.FailedImages != 1 || r.CompletedImages != 1 {
					t.Fatalf("counts = %+v", r)
				}
			}
		})
	}
}

func TestFailedScanDoesNotResolveFindings(t *testing.T) {
	h := newHarness(t, orchestrator.Options{MaxAttempts: 1})
	a := img("a", "prod/a")
	h.disc.set(a)
	h.sc.setVulns(a.Ref, crit("CVE-1"))
	h.start()
	h.scan(store.ScopeCluster, "")
	h.sc.setVulns(a.Ref)
	h.sc.queueErrs(a.Ref, fatal)
	r := h.scan(store.ScopeCluster, "")
	if r.Status != store.StatusFailed {
		t.Fatalf("run = %+v", r)
	}
	if f := h.findings(store.FindingFilter{Status: store.FindingOpen}); len(f) != 1 {
		t.Fatalf("failed scan resolved findings: %+v", f)
	}
}

func TestCancelPending(t *testing.T) {
	h := newHarness(t, orchestrator.Options{})
	ctx := context.Background()
	run := h.enqueue(store.ScopeCluster, "")
	got, err := h.o.Cancel(ctx, run.ID)
	if err != nil || got.Status != store.StatusCancelled || !got.CancelRequested || got.FinishedAt == nil {
		t.Fatalf("cancel = %+v, %v", got, err)
	}
	// Cancelling a terminal run is a no-op.
	again, err := h.o.Cancel(ctx, run.ID)
	if err != nil || again.Status != store.StatusCancelled {
		t.Fatalf("second cancel = %+v, %v", again, err)
	}
	if _, err := h.o.Cancel(ctx, "does-not-exist"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cancel unknown: %v", err)
	}
	h.disc.set(img("a", "prod/a"))
	h.start()
	// The cancelled run is never executed; a later run is.
	r := h.scan(store.ScopeCluster, "")
	if r.Status != store.StatusSucceeded || len(h.disc.Calls()) != 1 {
		t.Fatalf("run = %+v, discovery calls %v", r, h.disc.Calls())
	}
	if got, _ := h.st.GetScanRun(ctx, run.ID); got.Status != store.StatusCancelled || got.StartedAt != nil {
		t.Fatalf("cancelled run changed: %+v", got)
	}
}

func TestCancelRunning(t *testing.T) {
	h := newHarness(t, orchestrator.Options{MaxConcurrentJobs: 1})
	a, b, c := img("a", "prod/a"), img("b", "prod/b"), img("c", "prod/c")
	h.disc.set(a, b, c)
	h.sc.setVulns(a.Ref, crit("CVE-A"))
	h.sc.setBlock(b.Ref, true)
	h.start()
	run := h.enqueue(store.ScopeCluster, "")
	for {
		if tg := waitFor(t, h.sc.started); tg.ImageRef == b.Ref {
			break
		}
	}
	if _, err := h.o.Cancel(context.Background(), run.ID); err != nil {
		t.Fatal(err)
	}
	r := h.wait(run.ID)
	if r.Status != store.StatusCancelled || !r.CancelRequested {
		t.Fatalf("run = %+v", r)
	}
	st := map[string]string{}
	for _, j := range h.jobs(run.ID) {
		st[j.ImageKey] = j.Status
	}
	if st[a.Key] != store.StatusSucceeded || st[b.Key] != store.StatusCancelled || st[c.Key] != store.StatusCancelled {
		t.Fatalf("job statuses = %v", st)
	}
	for _, call := range h.sc.Calls() {
		if call.ImageRef == c.Ref {
			t.Fatal("image c scanned after cancellation")
		}
	}
	if ev := h.notif.of(config.EventScanFailed); len(ev) != 0 {
		t.Fatalf("cancelled run emitted scan_failed: %+v", ev)
	}
	// The queue keeps working afterwards.
	h.sc.setBlock(b.Ref, false)
	if r := h.scan(store.ScopeCluster, ""); r.Status != store.StatusSucceeded {
		t.Fatalf("follow-up run = %+v", r)
	}
}

func TestCancelDuringDiscovery(t *testing.T) {
	h := newHarness(t, orchestrator.Options{})
	h.disc.block = true
	h.start()
	run := h.enqueue(store.ScopeCluster, "")
	waitFor(t, h.disc.started)
	if _, err := h.o.Cancel(context.Background(), run.ID); err != nil {
		t.Fatal(err)
	}
	r := h.wait(run.ID)
	if r.Status != store.StatusCancelled {
		t.Fatalf("run cancelled during discovery = %s (%s)", r.Status, r.Error)
	}
	if ev := h.notif.of(config.EventScanFailed); len(ev) != 0 {
		t.Fatalf("cancelled run emitted scan_failed: %+v", ev)
	}
}

func TestConcurrencyBound(t *testing.T) {
	for _, max := range []int{1, 3} {
		t.Run("max"+string(rune('0'+max)), func(t *testing.T) {
			h := newHarness(t, orchestrator.Options{MaxConcurrentJobs: max})
			var imgs []discovery.Image
			for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
				imgs = append(imgs, img(n, "prod/"+n))
			}
			h.disc.set(imgs...)
			h.sc.delay = 20 * time.Millisecond
			h.start()
			r := h.scan(store.ScopeCluster, "")
			if r.Status != store.StatusSucceeded || r.CompletedImages != 8 {
				t.Fatalf("run = %+v", r)
			}
			if got := h.sc.MaxInflight(); got > max || got < 1 {
				t.Fatalf("max in-flight = %d, limit %d", got, max)
			}
			if max > 1 && h.sc.MaxInflight() < 2 {
				t.Fatalf("expected parallelism, max in-flight = %d", h.sc.MaxInflight())
			}
		})
	}
}

func TestRecoveryReattachesRunningJob(t *testing.T) {
	h := newHarness(t, orchestrator.Options{})
	ctx := context.Background()
	a, b := img("a", "prod/a"), img("b", "prod/b")
	h.disc.set(a, b)
	h.sc.setVulns(a.Ref, crit("CVE-A"))
	started := time.Now().UTC().Add(-time.Minute)
	// State left behind by a crashed controller.
	run := &store.ScanRun{ID: "crashed", Scope: store.ScopeCluster, Trigger: store.TriggerSchedule, Status: store.StatusRunning,
		TotalImages: 2, CreatedAt: started, StartedAt: &started}
	if err := h.st.CreateScanRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	for _, im := range []discovery.Image{a, b} {
		if err := h.st.UpsertImage(ctx, &store.Image{Key: im.Key, Repository: im.Repository, Ref: im.Ref, Deployed: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.st.CreateScanJobs(ctx, []store.ScanJob{
		{ID: "job-a", ScanRunID: "crashed", ImageKey: a.Key, ImageRef: a.Ref, Status: store.StatusRunning, Attempts: 1, StartedAt: &started, CreatedAt: started},
		{ID: "job-b", ScanRunID: "crashed", ImageKey: b.Key, ImageRef: b.Ref, Status: store.StatusPending, CreatedAt: started},
	}); err != nil {
		t.Fatal(err)
	}
	h.start()
	r := h.wait("crashed")
	if r.Status != store.StatusSucceeded || r.TotalImages != 2 || r.CompletedImages != 2 {
		t.Fatalf("recovered run = %+v", r)
	}
	if !r.StartedAt.Equal(started) {
		t.Fatalf("StartedAt changed: %v vs %v", r.StartedAt, started)
	}
	if n := len(h.disc.Calls()); n != 0 {
		t.Fatalf("resumed run re-ran discovery %d times", n)
	}
	attempts := map[string]int{}
	for _, c := range h.sc.Calls() {
		attempts[c.ScanJobID] = c.Attempt
	}
	if attempts["job-a"] != 1 || attempts["job-b"] != 1 || len(h.sc.Calls()) != 2 {
		t.Fatalf("scanner calls = %+v", h.sc.Calls())
	}
	for _, j := range h.jobs("crashed") {
		if j.Attempts != 1 || j.Status != store.StatusSucceeded {
			t.Fatalf("job = %+v", j)
		}
	}
	if ev := h.notif.of(config.EventNewCritical); len(ev) != 1 {
		t.Fatalf("new_critical after recovery = %+v", ev)
	}
}

func TestShutdownMidRunThenRestartResumes(t *testing.T) {
	h := newHarness(t, orchestrator.Options{MaxConcurrentJobs: 2})
	a, b := img("a", "prod/a"), img("b", "prod/b")
	h.disc.set(a, b)
	h.sc.setBlock(a.Ref, true)
	h.start()
	run := h.enqueue(store.ScopeCluster, "")
	for {
		if tg := waitFor(t, h.sc.started); tg.ImageRef == a.Ref {
			break
		}
	}
	h.stop()
	r, _ := h.st.GetScanRun(context.Background(), run.ID)
	if r.Status != store.StatusRunning {
		t.Fatalf("run after shutdown = %s, want running (left for recovery)", r.Status)
	}
	var jobA store.ScanJob
	for _, j := range h.jobs(run.ID) {
		if j.ImageKey == a.Key {
			jobA = j
		}
	}
	if jobA.Status != store.StatusRunning || jobA.Attempts != 1 {
		t.Fatalf("job a after shutdown = %+v", jobA)
	}
	if ev := h.notif.all(); len(ev) != 0 {
		t.Fatalf("shutdown emitted events: %+v", ev)
	}

	h.sc.setBlock(a.Ref, false)
	before := len(h.sc.Calls())
	h.restart()
	r = h.wait(run.ID)
	if r.Status != store.StatusSucceeded {
		t.Fatalf("resumed run = %+v", r)
	}
	for _, c := range h.sc.Calls()[before:] {
		if c.ImageRef == a.Ref && c.Attempt != 1 {
			t.Fatalf("re-attach used attempt %d", c.Attempt)
		}
	}
	if len(h.disc.Calls()) != 1 {
		t.Fatalf("discovery calls = %v", h.disc.Calls())
	}
}

func TestAcknowledgedFindingDoesNotRealert(t *testing.T) {
	h := newHarness(t, orchestrator.Options{})
	ctx := context.Background()
	a := img("a", "prod/a")
	h.disc.set(a)
	h.sc.setVulns(a.Ref, crit("CVE-1"))
	h.start()
	h.scan(store.ScopeCluster, "")
	fs := h.findings(store.FindingFilter{})
	now := time.Now().UTC()
	fs[0].AcknowledgedAt, fs[0].AckBy = &now, "token:admin"
	if err := h.st.SaveFinding(ctx, &fs[0]); err != nil {
		t.Fatal(err)
	}
	// Still present plus a brand-new critical: only the new one alerts.
	h.sc.setVulns(a.Ref, crit("CVE-1"), crit("CVE-2"))
	h.scan(store.ScopeCluster, "")
	ev := h.notif.of(config.EventNewCritical)
	if len(ev) != 2 || vulnIDs(ev[1].Findings) != "CVE-2" {
		t.Fatalf("new_critical events = %+v", ev)
	}
	f, _ := h.st.GetFinding(ctx, fs[0].ID)
	if f.AcknowledgedAt == nil || f.Status != store.FindingOpen {
		t.Fatalf("ack lost on refresh: %+v", f)
	}

	// Fixed then re-introduced: reopening clears the ack and alerts again.
	h.sc.setVulns(a.Ref, crit("CVE-2"))
	h.scan(store.ScopeCluster, "")
	h.sc.setVulns(a.Ref, crit("CVE-1"), crit("CVE-2"))
	h.scan(store.ScopeCluster, "")
	ev = h.notif.of(config.EventNewCritical)
	if len(ev) != 3 || vulnIDs(ev[2].Findings) != "CVE-1" {
		t.Fatalf("reopen should alert: %+v", ev)
	}
}

func TestSilencedFindingsDoNotAlert(t *testing.T) {
	h := newHarness(t, orchestrator.Options{})
	ctx := context.Background()
	silenced, sharedImg, unsilenced := img("s", "prod/s"), img("shared", "prod/x", "staging/x"), img("u", "prod/u")
	h.disc.set(silenced, sharedImg, unsilenced)
	h.sc.setVulns(silenced.Ref, crit("CVE-S"))
	h.sc.setVulns(sharedImg.Ref, crit("CVE-SH"))
	h.sc.setVulns(unsilenced.Ref, crit("CVE-U"), crit("CVE-IGNORED"))
	expired := time.Now().UTC().Add(-time.Hour)
	for _, s := range []store.Silence{
		{ID: "img", Kind: store.SilenceImage, Target: silenced.Repository},
		{ID: "ns", Kind: store.SilenceNamespace, Target: "staging"}, // shared image also runs in prod
		{ID: "vuln", Kind: store.SilenceVulnerability, Target: "CVE-IGNORED"},
		{ID: "old", Kind: store.SilenceVulnerability, Target: "CVE-U", ExpiresAt: &expired},
	} {
		s := s
		s.CreatedAt = time.Now().UTC()
		if err := h.st.CreateSilence(ctx, &s); err != nil {
			t.Fatal(err)
		}
	}
	h.start()
	h.scan(store.ScopeCluster, "")
	ev := h.notif.of(config.EventNewCritical)
	if len(ev) != 1 || vulnIDs(ev[0].Findings) != "CVE-SH,CVE-U" {
		t.Fatalf("new_critical = %+v", ev)
	}
	if n := len(h.findings(store.FindingFilter{Status: store.FindingOpen})); n != 4 {
		t.Fatalf("silenced findings must stay visible, open = %d", n)
	}
	// Resolutions of silenced findings stay quiet too.
	h.sc.setVulns(silenced.Ref)
	h.scan(store.ScopeCluster, "")
	if ev := h.notif.of(config.EventResolved); len(ev) != 0 {
		t.Fatalf("silenced resolution alerted: %+v", ev)
	}
}

func TestNonCriticalNewFindingsDoNotAlert(t *testing.T) {
	h := newHarness(t, orchestrator.Options{})
	a := img("a", "prod/a")
	h.disc.set(a)
	h.sc.setVulns(a.Ref, high("CVE-H"), scanner.Vulnerability{VulnerabilityID: "CVE-c", PkgName: "p", Severity: "critical"})
	h.start()
	r := h.scan(store.ScopeCluster, "")
	if r.NewFindings != 2 {
		t.Fatalf("run = %+v", r)
	}
	ev := h.notif.of(config.EventNewCritical)
	if len(ev) != 1 || vulnIDs(ev[0].Findings) != "CVE-c" {
		t.Fatalf("new_critical = %+v", ev)
	}
}

func TestSchedulerDue(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		spec     string
		runs     []store.ScanRun
		wantDue  bool
		wantNext time.Time
	}{
		{"no runs", "@every 1h", nil, true, now},
		{"recent run", "@every 1h", []store.ScanRun{{Scope: store.ScopeCluster, Status: store.StatusSucceeded, CreatedAt: now.Add(-10 * time.Minute)}}, false, now.Add(50 * time.Minute)},
		{"old run", "@every 1h", []store.ScanRun{{Scope: store.ScopeCluster, Status: store.StatusSucceeded, CreatedAt: now.Add(-2 * time.Hour)}}, true, now.Add(-time.Hour)},
		{"exactly due", "@every 1h", []store.ScanRun{{Scope: store.ScopeCluster, Status: store.StatusFailed, CreatedAt: now.Add(-time.Hour)}}, true, now},
		{"namespace runs ignored", "@every 1h", []store.ScanRun{
			{Scope: store.ScopeCluster, Status: store.StatusSucceeded, CreatedAt: now.Add(-3 * time.Hour)},
			{Scope: store.ScopeNamespace, Namespace: "prod", Status: store.StatusSucceeded, CreatedAt: now.Add(-time.Minute)},
		}, true, now.Add(-2 * time.Hour)},
		{"anchored at latest cluster run", "@every 12h", []store.ScanRun{
			{Scope: store.ScopeCluster, Status: store.StatusSucceeded, CreatedAt: now.Add(-24 * time.Hour)},
			{Scope: store.ScopeCluster, Status: store.StatusRunning, CreatedAt: now.Add(-time.Hour)},
		}, false, now.Add(11 * time.Hour)},
		{"cron", "0 3 * * *", []store.ScanRun{{Scope: store.ScopeCluster, Status: store.StatusSucceeded, CreatedAt: now.Add(-2 * time.Hour)}}, false, time.Date(2026, 5, 2, 3, 0, 0, 0, time.UTC)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := storetest.SQLite(t)
			o := orchestrator.New(st, &fakeDisc{}, newFakeScanner(), nil, orchestrator.Options{Now: func() time.Time { return now }}, logger)
			for i, r := range tc.runs {
				r.ID = string(rune('a' + i))
				r.Trigger = store.TriggerSchedule
				if err := st.CreateScanRun(context.Background(), &r); err != nil {
					t.Fatal(err)
				}
			}
			s, err := orchestrator.NewScheduler(o, st, tc.spec, true, logger)
			if err != nil {
				t.Fatal(err)
			}
			due, next, err := s.Due(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if due != tc.wantDue || !next.Equal(tc.wantNext) {
				t.Fatalf("Due = %v, %v; want %v, %v", due, next, tc.wantDue, tc.wantNext)
			}
		})
	}
}

func TestSchedulerConstruction(t *testing.T) {
	st := storetest.SQLite(t)
	o := orchestrator.New(st, &fakeDisc{}, newFakeScanner(), nil, orchestrator.Options{}, logger)
	if s, err := orchestrator.NewScheduler(o, st, "", true, logger); s != nil || err != nil {
		t.Fatalf("empty spec = %v, %v", s, err)
	}
	for _, bad := range []string{"every day", "@every banana", "* * *"} {
		if _, err := orchestrator.NewScheduler(o, st, bad, true, logger); err == nil {
			t.Errorf("spec %q accepted", bad)
		}
	}
	for _, good := range []string{"@every 12h", "@daily", "*/5 * * * *"} {
		if _, err := orchestrator.ParseSchedule(good); err != nil {
			t.Errorf("spec %q rejected: %v", good, err)
		}
	}
}

func TestSchedulerRunEnqueuesWhenDue(t *testing.T) {
	h := newHarness(t, orchestrator.Options{})
	s, err := orchestrator.NewScheduler(h.o, h.st, "@every 1h", true, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runs, _, _ := h.st.ListScanRuns(context.Background(), store.ScanRunFilter{})
		if len(runs) == 1 {
			if runs[0].Trigger != store.TriggerSchedule || runs[0].Scope != store.ScopeCluster {
				t.Fatalf("run = %+v", runs[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scheduler did not enqueue")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestSchedulerWithoutScanOnStartupWaitsOneInterval(t *testing.T) {
	h := newHarness(t, orchestrator.Options{})
	s, err := orchestrator.NewScheduler(h.o, h.st, "@every 1h", false, logger)
	if err != nil {
		t.Fatal(err)
	}
	due, next, err := s.Due(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if due {
		t.Fatalf("scan due immediately with scanOnStartup=false; next=%v", next)
	}
}

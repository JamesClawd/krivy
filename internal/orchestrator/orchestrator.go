// Package orchestrator runs scan runs from a persistent queue: it discovers
// images, fans out one scanner Job per image with bounded concurrency,
// reconciles findings and emits notifications. Runs execute one at a time so
// they never overlap; queue state lives in the database so a restarted
// controller resumes in-flight runs.
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/l4r-s/krivy/internal/config"
	"github.com/l4r-s/krivy/internal/discovery"
	"github.com/l4r-s/krivy/internal/findings"
	"github.com/l4r-s/krivy/internal/notify"
	"github.com/l4r-s/krivy/internal/scanner"
	"github.com/l4r-s/krivy/internal/store"
)

// Options configure the orchestrator.
type Options struct {
	MaxConcurrentJobs int
	MaxAttempts       int
	// RetryBackoff is the base delay between attempts of one image.
	RetryBackoff time.Duration
	// WatchNamespace restricts cluster scans to one namespace when set.
	WatchNamespace string
	Cluster        string
	Now            func() time.Time
}

// Orchestrator owns the scan queue.
type Orchestrator struct {
	st       store.Store
	disc     discovery.Discoverer
	scan     scanner.Scanner
	notifier notify.Notifier
	opts     Options
	log      *slog.Logger

	wake chan struct{}

	mu      sync.Mutex
	current string
	cancel  context.CancelCauseFunc
	// enqueueMu serializes the check-then-create in Enqueue.
	enqueueMu sync.Mutex
}

// New creates an orchestrator.
func New(st store.Store, disc discovery.Discoverer, sc scanner.Scanner, n notify.Notifier, opts Options, log *slog.Logger) *Orchestrator {
	if opts.MaxConcurrentJobs <= 0 {
		opts.MaxConcurrentJobs = 1
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = 2
	}
	if opts.RetryBackoff <= 0 {
		opts.RetryBackoff = 10 * time.Second
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if n == nil {
		n = notify.Nop{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &Orchestrator{st: st, disc: disc, scan: sc, notifier: n, opts: opts, log: log, wake: make(chan struct{}, 1)}
}

// ErrInvalidScope is returned for malformed scan requests.
var ErrInvalidScope = errors.New("invalid scan scope")

// Enqueue requests a scan. Equivalent pending/running work is deduplicated:
// an identical active run, or an active cluster run covering a namespace
// request, is returned instead of creating a new run. created reports
// whether a new run was queued.
func (o *Orchestrator) Enqueue(ctx context.Context, scope, namespace, trigger, actor string) (run *store.ScanRun, created bool, err error) {
	switch scope {
	case store.ScopeCluster:
		namespace = ""
	case store.ScopeNamespace:
		if namespace == "" {
			return nil, false, fmt.Errorf("%w: namespace is required for namespace scans", ErrInvalidScope)
		}
		if o.opts.WatchNamespace != "" && namespace != o.opts.WatchNamespace {
			return nil, false, fmt.Errorf("%w: krivy only watches namespace %q", ErrInvalidScope, o.opts.WatchNamespace)
		}
	default:
		return nil, false, fmt.Errorf("%w: scope must be cluster or namespace", ErrInvalidScope)
	}
	o.enqueueMu.Lock()
	defer o.enqueueMu.Unlock()
	active, err := o.st.ActiveScanRuns(ctx)
	if err != nil {
		return nil, false, err
	}
	for i := range active {
		a := &active[i]
		if a.CancelRequested {
			continue
		}
		if a.Scope == store.ScopeCluster || (a.Scope == scope && a.Namespace == namespace) {
			return a, false, nil
		}
	}
	run = &store.ScanRun{
		ID:          uuid.NewString(),
		Scope:       scope,
		Namespace:   namespace,
		Trigger:     trigger,
		RequestedBy: actor,
		Status:      store.StatusPending,
		CreatedAt:   o.opts.Now(),
	}
	if err := o.st.CreateScanRun(ctx, run); err != nil {
		return nil, false, err
	}
	o.log.Info("scan queued", "scan_id", run.ID, "scope", scope, "namespace", namespace, "trigger", trigger)
	o.signal()
	return run, true, nil
}

// Cancel requests cancellation of a pending or running run.
func (o *Orchestrator) Cancel(ctx context.Context, id string) (*store.ScanRun, error) {
	o.enqueueMu.Lock()
	defer o.enqueueMu.Unlock()
	run, err := o.st.GetScanRun(ctx, id)
	if err != nil {
		return nil, err
	}
	if run.Terminal() {
		return run, nil
	}
	run.CancelRequested = true
	if run.Status == store.StatusPending {
		now := o.opts.Now()
		run.Status = store.StatusCancelled
		run.FinishedAt = &now
	}
	if err := o.st.UpdateScanRun(ctx, run); err != nil {
		return nil, err
	}
	o.mu.Lock()
	if o.current == id && o.cancel != nil {
		o.cancel(scanner.ErrScanCancelled)
	}
	o.mu.Unlock()
	return run, nil
}

func (o *Orchestrator) signal() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// Run processes the queue until ctx is cancelled. It first recovers runs left
// running by a previous controller process.
func (o *Orchestrator) Run(ctx context.Context) error {
	if err := o.recover(ctx); err != nil {
		return fmt.Errorf("recover scan queue: %w", err)
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		for {
			processed, err := o.processNext(ctx)
			if err != nil && ctx.Err() == nil {
				o.log.Error("scan run processing failed", "error", err)
			}
			if !processed || ctx.Err() != nil {
				break
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-o.wake:
		case <-ticker.C:
		}
	}
}

// recover moves runs and jobs interrupted mid-flight back to pending. Job
// attempts are kept so the scanner re-attaches to the existing Kubernetes Job
// (Job names are deterministic per attempt) instead of starting a new one.
func (o *Orchestrator) recover(ctx context.Context) error {
	active, err := o.st.ActiveScanRuns(ctx)
	if err != nil {
		return err
	}
	for i := range active {
		r := &active[i]
		if r.Status != store.StatusRunning {
			continue
		}
		o.log.Warn("recovering interrupted scan run", "scan_id", r.ID)
		r.Status = store.StatusPending
		if err := o.st.UpdateScanRun(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// processNext runs the oldest pending run, if any.
func (o *Orchestrator) processNext(ctx context.Context) (bool, error) {
	active, err := o.st.ActiveScanRuns(ctx)
	if err != nil {
		return false, err
	}
	var run *store.ScanRun
	for i := range active {
		if active[i].Status == store.StatusPending {
			run = &active[i]
			break
		}
	}
	if run == nil {
		return false, nil
	}
	// Re-check the run and register it as current under enqueueMu, so a
	// concurrent Cancel either still sees it pending (and we skip it) or
	// finds o.current and cancels runCtx.
	o.enqueueMu.Lock()
	cur, err := o.st.GetScanRun(ctx, run.ID)
	if err != nil {
		o.enqueueMu.Unlock()
		return false, err
	}
	if cur.Status != store.StatusPending {
		o.enqueueMu.Unlock()
		return true, nil // cancelled after it was listed
	}
	run = cur
	runCtx, cancel := context.WithCancelCause(ctx)
	if run.CancelRequested {
		// Cancel was requested before a controller restart.
		cancel(scanner.ErrScanCancelled)
	}
	o.mu.Lock()
	o.current, o.cancel = run.ID, cancel
	o.mu.Unlock()
	o.enqueueMu.Unlock()
	defer func() {
		cancel(nil)
		o.mu.Lock()
		o.current, o.cancel = "", nil
		o.mu.Unlock()
	}()
	return true, o.execute(ctx, runCtx, run)
}

// execute performs one run. parent is the controller lifetime context;
// runCtx is additionally cancelled by Cancel.
func (o *Orchestrator) execute(parent, runCtx context.Context, run *store.ScanRun) error {
	log := o.log.With("scan_id", run.ID, "scope", run.Scope, "namespace", run.Namespace)
	now := o.opts.Now()
	run.Status = store.StatusRunning
	if run.StartedAt == nil {
		run.StartedAt = &now
	}
	if err := o.st.UpdateScanRun(parent, run); err != nil {
		return err
	}

	jobs, err := o.st.ListScanJobs(parent, run.ID)
	if err != nil {
		return err
	}
	var changes findings.Changes
	if len(jobs) == 0 {
		// Fresh run: discover, sync workloads and create per-image jobs.
		jobs, changes, err = o.prepare(runCtx, run)
		if err != nil {
			if parent.Err() != nil {
				return parent.Err() // controller shutting down: leave run for recovery
			}
			markCancelled(runCtx, run)
			return o.finish(parent, run, nil, findings.Changes{}, err)
		}
		run.TotalImages = len(jobs)
		if err := o.st.UpdateScanRun(parent, run); err != nil {
			return err
		}
		log.Info("scan run started", "images", len(jobs))
	} else {
		log.Info("resuming scan run", "images", len(jobs))
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, o.opts.MaxConcurrentJobs)
	)
	for i := range jobs {
		j := &jobs[i]
		if j.Status == store.StatusSucceeded || j.Status == store.StatusFailed || j.Status == store.StatusCancelled {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-runCtx.Done():
		}
		if runCtx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			// Work on a copy so updateProgress never reads a job mid-write.
			mu.Lock()
			jc := *j
			mu.Unlock()
			ch := o.runJob(parent, runCtx, run, &jc, log)
			mu.Lock()
			*j = jc
			changes.Add(ch)
			o.updateProgress(parent, run, jobs)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if parent.Err() != nil {
		// Shutdown: leave run/jobs for recovery on next start.
		return parent.Err()
	}
	markCancelled(runCtx, run)
	return o.finish(parent, run, jobs, changes, nil)
}

// markCancelled records a user cancellation from the runCtx cause rather
// than relying only on the persisted CancelRequested flag, which a
// concurrent progress save may have overwritten.
func markCancelled(runCtx context.Context, run *store.ScanRun) {
	if errors.Is(context.Cause(runCtx), scanner.ErrScanCancelled) {
		run.CancelRequested = true
	}
}

// prepare discovers images and persists workloads, images and scan jobs.
func (o *Orchestrator) prepare(ctx context.Context, run *store.ScanRun) ([]store.ScanJob, findings.Changes, error) {
	ns := run.Namespace
	if run.Scope == store.ScopeCluster && o.opts.WatchNamespace != "" {
		ns = o.opts.WatchNamespace
	}
	res, err := o.disc.Discover(ctx, ns)
	if err != nil {
		return nil, findings.Changes{}, fmt.Errorf("discovery: %w", err)
	}
	for _, w := range res.Warnings {
		o.log.Warn("discovery warning", "scan_id", run.ID, "warning", w)
	}
	now := o.opts.Now()
	var observed []store.Workload
	for _, img := range res.Images {
		if err := o.st.UpsertImage(ctx, &store.Image{
			Key: img.Key, Repository: img.Repository, Digest: img.Digest, Ref: img.Ref,
			FirstSeenAt: now, LastSeenAt: now, Deployed: true,
		}); err != nil {
			return nil, findings.Changes{}, err
		}
		for _, w := range img.Workloads {
			observed = append(observed, store.Workload{
				ImageKey: img.Key, Namespace: w.Namespace, Kind: w.Kind, Name: w.Name, Container: w.Container,
			})
		}
	}
	if err := o.st.SyncWorkloads(ctx, ns, observed, now); err != nil {
		return nil, findings.Changes{}, err
	}
	// Images that left the cluster no longer carry open findings.
	var ch findings.Changes
	resolved, err := findings.ResolveUndeployed(ctx, o.st, now)
	if err != nil {
		return nil, findings.Changes{}, err
	}
	ch.Resolved = resolved

	jobs := make([]store.ScanJob, 0, len(res.Images))
	for _, img := range res.Images {
		jobs = append(jobs, store.ScanJob{
			ID: uuid.NewString(), ScanRunID: run.ID, ImageKey: img.Key, ImageRef: img.Ref,
			Status: store.StatusPending, CreatedAt: now,
		})
	}
	sort.Slice(jobs, func(a, b int) bool { return jobs[a].ImageKey < jobs[b].ImageKey })
	if err := o.st.CreateScanJobs(ctx, jobs); err != nil {
		return nil, findings.Changes{}, err
	}
	return jobs, ch, nil
}

// runJob scans one image with retries and reconciles its findings.
func (o *Orchestrator) runJob(parent, runCtx context.Context, run *store.ScanRun, j *store.ScanJob, log *slog.Logger) findings.Changes {
	log = log.With("image", j.ImageKey)
	resumed := j.Status == store.StatusRunning
	for {
		if runCtx.Err() != nil {
			if parent.Err() == nil {
				o.markJob(parent, j, store.StatusCancelled, "scan cancelled", "")
			}
			return findings.Changes{}
		}
		now := o.opts.Now()
		if !resumed {
			j.Attempts++
		}
		resumed = false
		j.Status = store.StatusRunning
		j.StartedAt = &now
		j.Error = ""
		if err := o.st.UpdateScanJob(parent, j); err != nil {
			log.Error("persist scan job", "error", err)
		}
		res, err := o.scan.Scan(runCtx, scanner.Target{
			ScanJobID: j.ID, ImageKey: j.ImageKey, ImageRef: j.ImageRef, Attempt: j.Attempts,
		})
		if err == nil {
			ch, rerr := findings.ReconcileImage(parent, o.st, run.ID, j.ImageKey, res.Vulnerabilities, o.opts.Now())
			if rerr != nil {
				o.markJob(parent, j, store.StatusFailed, "persist findings: "+rerr.Error(), res.Diagnostics)
				return findings.Changes{}
			}
			j.K8sJobName = res.JobName
			j.VulnCount = len(res.Vulnerabilities)
			o.markJob(parent, j, store.StatusSucceeded, "", res.Diagnostics)
			if img, gerr := o.st.GetImage(parent, j.ImageKey); gerr == nil {
				t := o.opts.Now()
				img.LastScannedAt = &t
				if res.OS != "" {
					img.OS = res.OS
				}
				if res.ImageDigest != "" && img.Digest == "" {
					img.Digest = res.ImageDigest
				}
				_ = o.st.UpsertImage(parent, img)
			}
			log.Info("image scanned", "vulnerabilities", len(res.Vulnerabilities), "new", len(ch.New), "resolved", len(ch.Resolved))
			return ch
		}
		if runCtx.Err() != nil {
			continue // handled at loop top
		}
		diag := ""
		var se *scanner.Error
		if errors.As(err, &se) {
			diag = se.Diagnostics
		}
		if scanner.IsRetryable(err) && j.Attempts < o.opts.MaxAttempts {
			log.Warn("image scan failed, retrying", "attempt", j.Attempts, "error", err)
			j.Error = err.Error()
			j.Diagnostics = diag
			_ = o.st.UpdateScanJob(parent, j)
			select {
			case <-time.After(o.opts.RetryBackoff * time.Duration(j.Attempts)):
			case <-runCtx.Done():
			}
			continue
		}
		log.Warn("image scan failed", "attempt", j.Attempts, "error", err)
		o.markJob(parent, j, store.StatusFailed, err.Error(), diag)
		return findings.Changes{}
	}
}

func (o *Orchestrator) markJob(ctx context.Context, j *store.ScanJob, status, msg, diag string) {
	now := o.opts.Now()
	j.Status = status
	j.Error = truncate(msg, 4096)
	if diag != "" {
		j.Diagnostics = truncate(diag, 16384)
	}
	j.FinishedAt = &now
	if err := o.st.UpdateScanJob(ctx, j); err != nil {
		o.log.Error("persist scan job", "scan_job_id", j.ID, "error", err)
	}
}

func (o *Orchestrator) updateProgress(ctx context.Context, run *store.ScanRun, jobs []store.ScanJob) {
	done, failed := 0, 0
	for i := range jobs {
		switch jobs[i].Status {
		case store.StatusSucceeded:
			done++
		case store.StatusFailed:
			failed++
		}
	}
	run.CompletedImages, run.FailedImages = done, failed
	// Don't clobber CancelRequested set concurrently by Cancel.
	if cur, err := o.st.GetScanRun(ctx, run.ID); err == nil {
		run.CancelRequested = run.CancelRequested || cur.CancelRequested
	}
	if err := o.st.UpdateScanRun(ctx, run); err != nil {
		o.log.Error("persist scan progress", "scan_id", run.ID, "error", err)
	}
}

// finish computes the final status, persists it and notifies.
func (o *Orchestrator) finish(ctx context.Context, run *store.ScanRun, jobs []store.ScanJob, ch findings.Changes, runErr error) error {
	if cur, err := o.st.GetScanRun(ctx, run.ID); err == nil {
		run.CancelRequested = run.CancelRequested || cur.CancelRequested
	}
	now := o.opts.Now()
	run.FinishedAt = &now
	var failedRefs []string
	done, failed, cancelled := 0, 0, 0
	for i := range jobs {
		switch jobs[i].Status {
		case store.StatusSucceeded:
			done++
		case store.StatusFailed:
			failed++
			failedRefs = append(failedRefs, jobs[i].ImageRef)
		default:
			cancelled++
			if jobs[i].Status != store.StatusCancelled {
				o.markJob(ctx, &jobs[i], store.StatusCancelled, "scan cancelled", "")
			}
		}
	}
	run.CompletedImages, run.FailedImages = done, failed
	switch {
	case run.CancelRequested:
		// Checked before runErr: a cancellation during discovery surfaces as
		// a context error and must not be reported as a failed scan.
		run.Status = store.StatusCancelled
	case runErr != nil:
		run.Status = store.StatusFailed
		run.Error = truncate(runErr.Error(), 4096)
	case failed > 0 && done == 0:
		run.Status = store.StatusFailed
		run.Error = fmt.Sprintf("all %d image scans failed", failed)
	case failed > 0 || cancelled > 0:
		run.Status = store.StatusPartial
		run.Error = fmt.Sprintf("%d of %d image scans failed", failed, len(jobs))
	default:
		run.Status = store.StatusSucceeded
	}
	run.NewFindings, run.ResolvedCount = len(ch.New), len(ch.Resolved)
	if err := o.st.UpdateScanRun(ctx, run); err != nil {
		return err
	}
	o.log.Info("scan run finished", "scan_id", run.ID, "status", run.Status,
		"images", len(jobs), "failed", failed, "new_findings", len(ch.New), "resolved", len(ch.Resolved))
	o.emit(ctx, run, ch, failedRefs)
	return nil
}

func (o *Orchestrator) emit(ctx context.Context, run *store.ScanRun, ch findings.Changes, failedRefs []string) {
	scan := notify.ScanInfo{
		ID: run.ID, Scope: run.Scope, Namespace: run.Namespace, Status: run.Status, Trigger: run.Trigger,
		TotalImages: run.TotalImages, FailedImages: run.FailedImages, Error: run.Error,
	}
	if run.FinishedAt != nil {
		scan.FinishedAt = *run.FinishedAt
	}
	now := o.opts.Now()
	if run.Status == store.StatusFailed || run.Status == store.StatusPartial {
		if len(failedRefs) > 0 && scan.Error != "" {
			scan.Error += ": " + strings.Join(limit(failedRefs, 10), ", ")
		}
		o.send(ctx, notify.Event{Type: config.EventScanFailed, Scan: scan, Cluster: o.opts.Cluster, Time: now})
	}
	if len(ch.New) == 0 && len(ch.Resolved) == 0 {
		return
	}
	silences, err := o.st.ListSilences(ctx, &now)
	if err != nil {
		o.log.Error("load silences", "error", err)
		return
	}
	policy := findings.NewPolicy(silences, now)
	ctxInfo := newInfoBuilder(ctx, o.st)
	var newInfos, resolvedInfos []notify.FindingInfo
	for i := range ch.New {
		f := &ch.New[i]
		info, repo, nss := ctxInfo.build(f)
		if policy.ShouldAlertNew(f, repo, nss) && strings.EqualFold(f.Severity, "CRITICAL") {
			newInfos = append(newInfos, info)
		}
	}
	for i := range ch.Resolved {
		f := &ch.Resolved[i]
		info, repo, nss := ctxInfo.build(f)
		if policy.ShouldAlertResolved(f, repo, nss) {
			resolvedInfos = append(resolvedInfos, info)
		}
	}
	if len(newInfos) > 0 {
		o.send(ctx, notify.Event{Type: config.EventNewCritical, Scan: scan, Findings: newInfos, Cluster: o.opts.Cluster, Time: now})
	}
	if len(resolvedInfos) > 0 {
		o.send(ctx, notify.Event{Type: config.EventResolved, Scan: scan, Findings: resolvedInfos, Cluster: o.opts.Cluster, Time: now})
	}
}

func (o *Orchestrator) send(ctx context.Context, ev notify.Event) {
	if err := o.notifier.Notify(ctx, ev); err != nil {
		o.log.Error("notify", "event", ev.Type, "scan_id", ev.Scan.ID, "error", err)
	}
}

// infoBuilder caches image and workload lookups while building events.
type infoBuilder struct {
	ctx       context.Context
	st        store.Store
	images    map[string]*store.Image
	workloads map[string][]store.Workload
}

func newInfoBuilder(ctx context.Context, st store.Store) *infoBuilder {
	return &infoBuilder{ctx: ctx, st: st, images: map[string]*store.Image{}, workloads: map[string][]store.Workload{}}
}

func (b *infoBuilder) build(f *store.Finding) (notify.FindingInfo, string, []string) {
	img, ok := b.images[f.ImageKey]
	if !ok {
		img, _ = b.st.GetImage(b.ctx, f.ImageKey)
		b.images[f.ImageKey] = img
	}
	ws, ok := b.workloads[f.ImageKey]
	if !ok {
		ws, _ = b.st.ListWorkloads(b.ctx, []string{f.ImageKey}, true)
		b.workloads[f.ImageKey] = ws
	}
	nsSet := map[string]bool{}
	var nss, wls []string
	for _, w := range ws {
		if !nsSet[w.Namespace] {
			nsSet[w.Namespace] = true
			nss = append(nss, w.Namespace)
		}
		wls = append(wls, w.Namespace+"/"+w.Kind+"/"+w.Name)
	}
	info := notify.FindingInfo{
		ID: f.ID, VulnerabilityID: f.VulnerabilityID, Severity: f.Severity, PkgName: f.PkgName,
		InstalledVersion: f.InstalledVersion, FixedVersion: f.FixedVersion, Title: f.Title,
		PrimaryURL: f.PrimaryURL, ImageKey: f.ImageKey, ImageRef: f.ImageKey,
		Namespaces: nss, Workloads: dedupeSorted(wls),
	}
	repo := ""
	if img != nil {
		info.ImageRef = img.Ref
		repo = img.Repository
	}
	return info, repo, nss
}

func dedupeSorted(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func limit(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], fmt.Sprintf("and %d more", len(s)-n))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

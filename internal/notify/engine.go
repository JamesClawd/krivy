package notify

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/l4r-s/krivy/internal/config"
	"github.com/l4r-s/krivy/internal/store"
)

const (
	defaultQueueSize     = 256
	defaultWorkers       = 4
	defaultBackoffBase   = time.Second
	defaultBackoffMax    = 2 * time.Minute
	defaultRetryAfterCap = 5 * time.Minute
	defaultStaleAfter    = 5 * time.Minute
	maxLastErrorLen      = 1024
	maxRespSnippet       = 256
	userAgent            = "krivy-notifier/1"
)

// Engine is the webhook Notifier. Notify records a pending delivery (deduped)
// and enqueues it; Start runs workers that render, send and retry.
type Engine struct {
	cfg    config.NotificationsConfig
	st     store.Store
	log    *slog.Logger
	dests  []*destination
	client *http.Client

	now           func() time.Time
	sleep         func(ctx context.Context, d time.Duration) error
	queueSize     int
	workers       int
	backoffBase   time.Duration
	backoffMax    time.Duration
	retryAfterCap time.Duration
	staleAfter    time.Duration
	maxBodyBytes  int
	renderTimeout time.Duration
	ipGuard       func(netip.Addr) error

	queue   chan job
	mu      sync.RWMutex
	closed  bool
	started bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	once    sync.Once
}

var _ Notifier = (*Engine)(nil)

type destination struct {
	cfg     config.WebhookDestination
	tmpl    *template.Template // nil => default body
	events  map[string]bool
	nsAllow map[string]bool // nil => all namespaces
	isJSON  bool
	secrets []string // values to redact from errors
}

type job struct {
	dest     *destination
	ev       Event // already filtered for dest
	delivery *store.NotificationDelivery
}

// Option customizes an Engine (mostly for tests).
type Option func(*Engine)

// WithHTTPClient replaces the HTTP client. The SSRF dial guard is then the
// caller's responsibility; redirects are still never followed.
func WithHTTPClient(c *http.Client) Option { return func(e *Engine) { e.client = c } }

// WithClock sets the time source.
func WithClock(now func() time.Time) Option { return func(e *Engine) { e.now = now } }

// WithSleep sets the context-aware sleep used between retries.
func WithSleep(f func(ctx context.Context, d time.Duration) error) Option {
	return func(e *Engine) { e.sleep = f }
}

// WithIPGuard replaces the dial-time address check (default CheckIP).
func WithIPGuard(f func(netip.Addr) error) Option { return func(e *Engine) { e.ipGuard = f } }

// WithQueueSize sets the in-memory queue capacity.
func WithQueueSize(n int) Option { return func(e *Engine) { e.queueSize = n } }

// WithWorkers sets the number of delivery workers.
func WithWorkers(n int) Option { return func(e *Engine) { e.workers = n } }

// WithBackoff sets exponential backoff base and maximum.
func WithBackoff(base, max time.Duration) Option {
	return func(e *Engine) { e.backoffBase, e.backoffMax = base, max }
}

// WithRetryAfterCap caps how long a Retry-After header can delay a retry.
func WithRetryAfterCap(d time.Duration) Option { return func(e *Engine) { e.retryAfterCap = d } }

// WithStaleAfter sets the age after which pending deliveries found at Start
// are marked failed.
func WithStaleAfter(d time.Duration) Option { return func(e *Engine) { e.staleAfter = d } }

// WithRenderLimits sets the rendered body size cap and template timeout.
func WithRenderLimits(maxBytes int, timeout time.Duration) Option {
	return func(e *Engine) { e.maxBodyBytes, e.renderTimeout = maxBytes, timeout }
}

// New validates cfg, parses all templates (failing fast) and dry-runs each
// against a synthetic event. It does not start delivery; call Start.
func New(cfg config.NotificationsConfig, st store.Store, logger *slog.Logger, opts ...Option) (*Engine, error) {
	if st == nil {
		return nil, errors.New("notify: store is required")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	e := &Engine{
		cfg:           cfg,
		st:            st,
		log:           logger.With("component", "notify"),
		now:           time.Now,
		sleep:         sleepCtx,
		queueSize:     defaultQueueSize,
		workers:       defaultWorkers,
		backoffBase:   defaultBackoffBase,
		backoffMax:    defaultBackoffMax,
		retryAfterCap: defaultRetryAfterCap,
		staleAfter:    defaultStaleAfter,
		maxBodyBytes:  DefaultMaxBodyBytes,
		renderTimeout: DefaultRenderTimeout,
		ipGuard:       CheckIP,
	}
	for _, o := range opts {
		o(e)
	}
	if e.queueSize < 1 {
		e.queueSize = 1
	}
	if e.workers < 1 {
		e.workers = 1
	}
	e.queue = make(chan job, e.queueSize)
	if e.client == nil {
		e.client = e.defaultClient()
	} else {
		c := *e.client
		e.client = &c
	}
	e.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	funcs := funcMap(e.now)
	seen := map[string]bool{}
	for _, dc := range cfg.Destinations {
		d, err := e.buildDestination(dc, funcs)
		if err != nil {
			return nil, fmt.Errorf("notify: destination %q: %w", dc.Name, err)
		}
		if seen[dc.Name] {
			return nil, fmt.Errorf("notify: duplicate destination %q", dc.Name)
		}
		seen[dc.Name] = true
		e.dests = append(e.dests, d)
	}
	return e, nil
}

func (e *Engine) defaultClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if !e.cfg.AllowPrivateNetworks {
		dialer.Control = ssrfControl(e.ipGuard)
	}
	tr := &http.Transport{
		// No proxy: a proxy would make the dial guard check the proxy, not the target.
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{Transport: tr}
}

func (e *Engine) buildDestination(dc config.WebhookDestination, funcs template.FuncMap) (*destination, error) {
	if dc.Name == "" {
		return nil, errors.New("name is required")
	}
	if dc.Method == "" {
		dc.Method = http.MethodPost
	}
	dc.Method = strings.ToUpper(dc.Method)
	if dc.ContentType == "" {
		dc.ContentType = "application/json"
	}
	if dc.Timeout.Duration <= 0 {
		dc.Timeout.Duration = 10 * time.Second
	}
	if dc.MaxRetries < 0 {
		dc.MaxRetries = 0
	}
	u, err := url.Parse(dc.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("url must be an absolute http(s) URL")
	}
	d := &destination{
		cfg:    dc,
		events: map[string]bool{},
		isJSON: isJSONContentType(dc.ContentType),
	}
	for _, ev := range dc.Events {
		d.events[ev] = true
	}
	if len(dc.Namespaces) > 0 {
		d.nsAllow = map[string]bool{}
		for _, ns := range dc.Namespaces {
			d.nsAllow[ns] = true
		}
	}
	d.secrets = secretStrings(dc, u)
	if strings.TrimSpace(dc.Template) != "" {
		t, err := parseTemplate(dc.Name, dc.Template, funcs)
		if err != nil {
			return nil, fmt.Errorf("invalid template: %w", err)
		}
		d.tmpl = t
	}
	// Dry-run every subscribed event type so typos (e.g. a missing secret key)
	// and non-JSON output fail at startup rather than at 3am.
	for _, evType := range dc.Events {
		if _, err := e.render(d, sampleEvent(evType, e.now())); err != nil {
			return nil, fmt.Errorf("template dry-run for %s: %w", evType, err)
		}
	}
	return d, nil
}

func secretStrings(dc config.WebhookDestination, u *url.URL) []string {
	var out []string
	add := func(s string) {
		if len(s) >= 4 {
			out = append(out, s, url.PathEscape(s), url.QueryEscape(s))
		}
	}
	for _, v := range dc.Headers {
		add(v)
		// Also the credential part of "Bearer xyz" style headers.
		if _, after, ok := strings.Cut(v, " "); ok {
			add(after)
		}
	}
	for _, v := range dc.Secrets {
		add(v)
	}
	add(dc.URL)
	add(u.Path)
	add(u.RawQuery)
	if u.User != nil {
		add(u.User.String())
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if len(seg) >= 8 {
			add(seg)
		}
	}
	for _, vs := range u.Query() {
		for _, v := range vs {
			add(v)
		}
	}
	// Longest first so substrings don't break larger matches.
	slices.SortFunc(out, func(a, b string) int { return len(b) - len(a) })
	return slices.Compact(out)
}

func (d *destination) redact(s string) string {
	for _, sec := range d.secrets {
		s = strings.ReplaceAll(s, sec, "[REDACTED]")
	}
	if len(s) > maxLastErrorLen {
		s = s[:maxLastErrorLen] + "…"
	}
	return strings.ToValidUTF8(s, "")
}

// sampleEvent is a synthetic event for template dry-runs and previews.
func sampleEvent(evType string, now time.Time) Event {
	ev := Event{
		Type:    evType,
		Cluster: "sample-cluster",
		Time:    now,
		Scan: ScanInfo{
			ID: "00000000-0000-4000-8000-000000000000", Scope: "cluster", Status: "succeeded",
			Trigger: "schedule", TotalImages: 1, FinishedAt: now,
		},
	}
	if evType == config.EventScanFailed {
		ev.Scan.Status = "failed"
		ev.Scan.Error = "sample error"
		return ev
	}
	ev.Findings = []FindingInfo{{
		ID: "sample", VulnerabilityID: "CVE-2024-0001", Severity: "CRITICAL", PkgName: "openssl",
		InstalledVersion: "3.0.0", FixedVersion: "3.0.1", Title: "Sample vulnerability",
		PrimaryURL: "https://avd.aquasec.com/nvd/cve-2024-0001", ImageKey: "sha256:sample",
		ImageRef: "registry.example.com/app:1.0", Namespaces: []string{"default"},
		Workloads: []string{"default/Deployment/app"},
	}}
	return ev
}

// Render renders the body destName would send for ev (after filtering). It
// returns (nil, nil) if the destination would skip the event.
func (e *Engine) Render(destName string, ev Event) ([]byte, error) {
	for _, d := range e.dests {
		if d.cfg.Name == destName {
			fev, ok := d.filter(ev)
			if !ok {
				return nil, nil
			}
			return e.render(d, fev)
		}
	}
	return nil, fmt.Errorf("unknown destination %q", destName)
}

// render produces the request body. Errors are non-retryable.
func (e *Engine) render(d *destination, ev Event) ([]byte, error) {
	var body []byte
	if d.tmpl == nil {
		if ev.Findings == nil {
			ev.Findings = []FindingInfo{}
		}
		b, err := json.Marshal(ev)
		if err != nil {
			return nil, err
		}
		body = b
	} else {
		secrets := map[string]string{}
		for k, v := range d.cfg.Secrets {
			secrets[k] = v
		}
		findings := ev.Findings
		if findings == nil {
			findings = []FindingInfo{}
		}
		data := TemplateData{
			Event:    EventMeta{Type: ev.Type, Time: ev.Time, Cluster: ev.Cluster},
			Scan:     ev.Scan,
			Findings: findings,
			Count:    len(findings),
			Secrets:  secrets,
			BaseURL:  strings.TrimRight(e.cfg.BaseURL, "/"),
		}
		b, err := execute(d.tmpl, data, e.maxBodyBytes, e.renderTimeout)
		if err != nil {
			return nil, fmt.Errorf("render: %s", d.redact(err.Error()))
		}
		body = b
	}
	if len(body) > e.maxBodyBytes {
		return nil, fmt.Errorf("%w (%d bytes)", errBodyTooLarge, e.maxBodyBytes)
	}
	if d.isJSON && !json.Valid(body) {
		return nil, errors.New("rendered body is not valid JSON (use the json function to embed values)")
	}
	return body, nil
}

// filter applies the destination's event and namespace filters.
func (d *destination) filter(ev Event) (Event, bool) {
	if !d.events[ev.Type] {
		return ev, false
	}
	if d.nsAllow == nil {
		return ev, true
	}
	if ev.Type == config.EventScanFailed {
		// Namespace-scoped scans outside the filter are someone else's.
		if ev.Scan.Namespace != "" && !d.nsAllow[ev.Scan.Namespace] {
			return ev, false
		}
		ev.Findings = nil
		return ev, true
	}
	var kept []FindingInfo
	for _, f := range ev.Findings {
		var ns []string
		for _, n := range f.Namespaces {
			if d.nsAllow[n] {
				ns = append(ns, n)
			}
		}
		if len(ns) == 0 {
			continue
		}
		var wl []string
		for _, w := range f.Workloads {
			if n, _, ok := strings.Cut(w, "/"); ok && d.nsAllow[n] {
				wl = append(wl, w)
			}
		}
		f.Namespaces, f.Workloads = ns, wl
		kept = append(kept, f)
	}
	if len(kept) == 0 {
		return ev, false
	}
	ev.Findings = kept
	return ev, true
}

// DedupKey identifies one (destination, event type, scan, finding set).
func DedupKey(dest, evType, scanID string, findingIDs []string) string {
	ids := slices.Clone(findingIDs)
	slices.Sort(ids)
	h := sha256.New()
	h.Write([]byte(dest + "\x00" + evType + "\x00" + scanID + "\x00" + strings.Join(ids, "\x00")))
	return hex.EncodeToString(h.Sum(nil))[:48]
}

// Notify records and enqueues one delivery per matching destination. It never
// performs network I/O; duplicates (same dedup key) are skipped silently.
func (e *Engine) Notify(ctx context.Context, ev Event) error {
	if ev.Time.IsZero() {
		ev.Time = e.now().UTC()
	}
	var errs []error
	for _, d := range e.dests {
		fev, ok := d.filter(ev)
		if !ok {
			continue
		}
		// The worker runs later; never share slices with the caller.
		fev.Findings = cloneFindings(fev.Findings)
		ids := make([]string, len(fev.Findings))
		for i, f := range fev.Findings {
			ids[i] = f.ID
		}
		now := e.now().UTC()
		del := &store.NotificationDelivery{
			ID:          newID(),
			Destination: d.cfg.Name,
			Event:       ev.Type,
			DedupKey:    DedupKey(d.cfg.Name, ev.Type, ev.Scan.ID, ids),
			ScanRunID:   ev.Scan.ID,
			Status:      store.DeliveryPending,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := e.st.CreateDelivery(ctx, del); err != nil {
			if errors.Is(err, store.ErrDuplicate) {
				e.log.Debug("duplicate notification skipped", "destination", d.cfg.Name, "event", ev.Type, "scan", ev.Scan.ID)
				continue
			}
			errs = append(errs, fmt.Errorf("record delivery for %s: %w", d.cfg.Name, err))
			continue
		}
		if reason := e.enqueue(job{dest: d, ev: fev, delivery: del}); reason != "" {
			e.log.Warn("notification dropped", "destination", d.cfg.Name, "event", ev.Type, "reason", reason)
			e.finish(del, store.DeliveryFailed, 0, reason)
		}
	}
	return errors.Join(errs...)
}

func (e *Engine) enqueue(j job) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return "notifier closed"
	}
	select {
	case e.queue <- j:
		return ""
	default:
		return "notification queue full"
	}
}

// Start marks stale pending deliveries from a previous process as failed and
// launches the delivery workers. Workers stop when ctx is cancelled or Close
// is called.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	if e.started || e.closed {
		e.mu.Unlock()
		return errors.New("notify: engine already started or closed")
	}
	e.started = true
	wctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.mu.Unlock()

	if err := e.failStale(ctx); err != nil {
		e.log.Warn("could not mark stale deliveries", "error", err)
	}
	for range e.workers {
		e.wg.Add(1)
		go e.worker(wctx)
	}
	return nil
}

func (e *Engine) failStale(ctx context.Context) error {
	pending, err := e.st.ListDeliveries(ctx, store.DeliveryPending, 500)
	if err != nil {
		return err
	}
	cutoff := e.now().Add(-e.staleAfter)
	for i := range pending {
		d := &pending[i]
		if d.CreatedAt.Before(cutoff) {
			e.finish(d, store.DeliveryFailed, d.ResponseCode, "interrupted by restart")
		}
	}
	return nil
}

// Close stops accepting events, cancels in-flight deliveries and waits for
// workers. Queued or interrupted deliveries are recorded as failed. It is
// safe to call more than once.
func (e *Engine) Close() error {
	e.once.Do(func() {
		e.mu.Lock()
		e.closed = true
		cancel := e.cancel
		e.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		e.wg.Wait()
		for {
			select {
			case j := <-e.queue:
				e.finish(j.delivery, store.DeliveryFailed, 0, "interrupted by shutdown")
			default:
				return
			}
		}
	})
	return nil
}

func (e *Engine) worker(ctx context.Context) {
	defer e.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-e.queue:
			e.deliver(ctx, j)
		}
	}
}

// attemptResult describes one HTTP attempt.
type attemptResult struct {
	code       int
	err        string
	retryable  bool
	retryAfter time.Duration
}

func (e *Engine) deliver(ctx context.Context, j job) {
	d, del := j.dest, j.delivery
	body, err := e.render(d, j.ev)
	if err != nil {
		e.log.Error("notification render failed", "destination", d.cfg.Name, "event", del.Event, "error", d.redact(err.Error()))
		e.finish(del, store.DeliveryFailed, 0, err.Error())
		return
	}
	maxAttempts := 1 + d.cfg.MaxRetries
	for attempt := 1; ; attempt++ {
		res := e.attempt(ctx, d, body)
		del.Attempts = attempt
		if res.err == "" {
			e.finish(del, store.DeliveryDelivered, res.code, "")
			e.log.Info("notification delivered", "destination", d.cfg.Name, "event", del.Event, "attempts", attempt, "status", res.code)
			return
		}
		if ctx.Err() != nil {
			e.finish(del, store.DeliveryFailed, res.code, "interrupted by shutdown: "+res.err)
			return
		}
		if !res.retryable || attempt >= maxAttempts {
			e.log.Warn("notification failed", "destination", d.cfg.Name, "event", del.Event, "attempts", attempt, "status", res.code, "error", res.err)
			e.finish(del, store.DeliveryFailed, res.code, res.err)
			return
		}
		// Record progress, then back off.
		del.ResponseCode, del.LastError = res.code, d.redact(res.err)
		e.update(del)
		wait := e.backoff(attempt)
		if res.retryAfter > 0 {
			wait = max(wait, min(res.retryAfter, e.retryAfterCap))
		}
		if err := e.sleep(ctx, wait); err != nil {
			e.finish(del, store.DeliveryFailed, res.code, "interrupted by shutdown: "+res.err)
			return
		}
	}
}

func (e *Engine) attempt(ctx context.Context, d *destination, body []byte) attemptResult {
	actx, cancel := context.WithTimeout(ctx, d.cfg.Timeout.Duration)
	defer cancel()
	req, err := http.NewRequestWithContext(actx, d.cfg.Method, d.cfg.URL, strings.NewReader(string(body)))
	if err != nil {
		return attemptResult{err: "build request: " + d.redact(err.Error())}
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", d.cfg.ContentType)
	for k, v := range d.cfg.Headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL, which may embed a token
		}
		var be *BlockedAddressError
		if errors.As(err, &be) {
			return attemptResult{err: be.Error()}
		}
		msg := err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			msg = fmt.Sprintf("timeout after %s: %s", d.cfg.Timeout.Duration, msg)
		}
		return attemptResult{err: d.redact(msg), retryable: true}
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespSnippet))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	code := resp.StatusCode
	if code >= 200 && code < 300 {
		return attemptResult{code: code}
	}
	res := attemptResult{code: code}
	res.err = fmt.Sprintf("HTTP %d", code)
	if s := strings.TrimSpace(string(snippet)); s != "" {
		res.err += ": " + d.redact(s)
	}
	switch {
	case code >= 300 && code < 400:
		res.err += " (redirects are not followed)"
	case code == http.StatusTooManyRequests:
		res.retryable = true
		res.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), e.now())
	case code == http.StatusRequestTimeout || code >= 500:
		res.retryable = true
		if code == http.StatusServiceUnavailable {
			res.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), e.now())
		}
	}
	return res
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// backoff returns base*2^(attempt-1) capped at max, with ±50% jitter.
func (e *Engine) backoff(attempt int) time.Duration {
	d := e.backoffBase
	for i := 1; i < attempt && d < e.backoffMax; i++ {
		d *= 2
	}
	d = min(d, e.backoffMax)
	if d <= 1 {
		return d
	}
	half := d / 2
	return half + rand.N(d-half+1) //nolint:gosec // retry jitter, not security-sensitive
}

func (e *Engine) finish(del *store.NotificationDelivery, status string, code int, lastErr string) {
	del.Status = status
	if code != 0 {
		del.ResponseCode = code
	}
	del.LastError = lastErr
	if lastErr != "" {
		// Callers pass already-redacted text; still cap the length.
		if len(del.LastError) > maxLastErrorLen {
			del.LastError = strings.ToValidUTF8(del.LastError[:maxLastErrorLen], "") + "…"
		}
	}
	if status == store.DeliveryDelivered {
		t := e.now().UTC()
		del.DeliveredAt = &t
	}
	e.update(del)
}

func (e *Engine) update(del *store.NotificationDelivery) {
	del.UpdatedAt = e.now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.st.UpdateDelivery(ctx, del); err != nil {
		e.log.Error("could not update delivery record", "delivery", del.ID, "error", err)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// newID returns a random RFC 4122 version 4 UUID.
func newID() string {
	var b [16]byte
	_, _ = crand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func cloneFindings(in []FindingInfo) []FindingInfo {
	if in == nil {
		return nil
	}
	out := make([]FindingInfo, len(in))
	for i, f := range in {
		f.Namespaces = slices.Clone(f.Namespaces)
		f.Workloads = slices.Clone(f.Workloads)
		out[i] = f
	}
	return out
}

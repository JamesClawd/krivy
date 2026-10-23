package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/l4r-s/krivy/internal/config"
	"github.com/l4r-s/krivy/internal/store"
)

func newStore(t *testing.T) *store.GormStore {
	t.Helper()
	st, err := store.Open("sqlite", filepath.Join(t.TempDir(), "notify.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func dest(name, url string, mod ...func(*config.WebhookDestination)) config.WebhookDestination {
	d := config.WebhookDestination{
		Name: name, URL: url, Method: "POST", ContentType: "application/json",
		Events:     []string{config.EventNewCritical, config.EventResolved, config.EventScanFailed},
		Timeout:    config.Duration{Duration: 2 * time.Second},
		MaxRetries: 3,
	}
	for _, m := range mod {
		m(&d)
	}
	return d
}

func testEvent(findings ...FindingInfo) Event {
	if len(findings) == 0 {
		findings = []FindingInfo{{
			ID: "f1", VulnerabilityID: "CVE-2024-1", Severity: "CRITICAL", PkgName: "openssl",
			InstalledVersion: "1.0", FixedVersion: "1.1", ImageRef: "nginx:1",
			Namespaces: []string{"default"}, Workloads: []string{"default/Deployment/web"},
		}}
	}
	return Event{
		Type:     config.EventNewCritical,
		Scan:     ScanInfo{ID: "scan-1", Scope: "cluster", Status: "succeeded"},
		Findings: findings,
		Cluster:  "prod",
		Time:     time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

type recorder struct {
	mu     sync.Mutex
	bodies []string
	hdrs   []http.Header
	calls  atomic.Int32
}

func (r *recorder) record(req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.bodies = append(r.bodies, string(b))
	r.hdrs = append(r.hdrs, req.Header.Clone())
	r.mu.Unlock()
	r.calls.Add(1)
}

// fastOpts makes retries instantaneous and records sleeps.
func fastOpts(sleeps *[]time.Duration) []Option {
	var mu sync.Mutex
	return []Option{
		WithBackoff(time.Millisecond, 4*time.Millisecond),
		WithSleep(func(ctx context.Context, d time.Duration) error {
			if sleeps != nil {
				mu.Lock()
				*sleeps = append(*sleeps, d)
				mu.Unlock()
			}
			return ctx.Err()
		}),
	}
}

func startEngine(t *testing.T, cfg config.NotificationsConfig, st store.Store, opts ...Option) *Engine {
	t.Helper()
	e, err := New(cfg, st, nil, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// waitDelivery polls until all deliveries of dest are final.
func waitFinal(t *testing.T, st store.Store, n int) []store.NotificationDelivery {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		all, err := st.ListDeliveries(context.Background(), "", 100)
		if err != nil {
			t.Fatal(err)
		}
		done := 0
		for _, d := range all {
			if d.Status != store.DeliveryPending {
				done++
			}
		}
		if len(all) >= n && done == len(all) {
			return all
		}
		time.Sleep(10 * time.Millisecond)
	}
	all, _ := st.ListDeliveries(context.Background(), "", 100)
	t.Fatalf("deliveries not final: %+v", all)
	return nil
}

// ---- templating ----

func TestTemplateEscapingAndLogic(t *testing.T) {
	st := newStore(t)
	tmpl := `{"chat": {{ json .Secrets.chat }}, "count": {{ .Count }},
"items": [{{ range $i, $f := .Findings }}{{ if $i }},{{ end }}{{ json $f.Title }}{{ end }}],
"inline": "x {{ jsonEscape (index .Findings 0).Title }} y",
"q": {{ quote (index .Findings 0).Title }},
"crit": {{ countBySeverity .Findings "critical" }},
"sev": {{ json (countBySeverity .Findings) }},
"up": {{ json (upper .Event.Type) }}, "low": {{ json (lower "ABC") }},
"tr": {{ json (truncate 3 "abcdef") }}, "def": {{ json (default "none" .Event.Cluster) }},
"first": {{ len (first 1 .Findings) }}, "join": {{ json (join "," (index .Findings 0).Namespaces) }},
"t": {{ json (formatTime "2006-01-02" .Event.Time) }}, "now": {{ json (formatTime "2006" now) }},
"base": {{ json .BaseURL }}{{ if eq .Event.Type "new_critical" }}, "new": true{{ end }}}`
	cfg := config.NotificationsConfig{BaseURL: "https://k.example/", Destinations: []config.WebhookDestination{
		dest("d", "https://example.com/hook", func(d *config.WebhookDestination) {
			d.Template = tmpl
			d.Events = []string{config.EventNewCritical}
			d.Secrets = map[string]string{"chat": "-100\"123"}
		}),
	}}
	e, err := New(cfg, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	evil := "a\"b\\c\nd</script><b>&é😀 \x00"
	ev := testEvent(
		FindingInfo{ID: "1", Title: evil, Severity: "CRITICAL", Namespaces: []string{"a", "b"}},
		FindingInfo{ID: "2", Title: "plain", Severity: "HIGH", Namespaces: []string{"c"}},
	)
	body, err := e.Render("d", ev)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "</script>") {
		t.Errorf("unescaped </script> in %s", body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("invalid json %s: %v", body, err)
	}
	if out["chat"] != "-100\"123" || out["count"].(float64) != 2 {
		t.Errorf("unexpected %v", out)
	}
	if items := out["items"].([]any); items[0] != evil || items[1] != "plain" {
		t.Errorf("items roundtrip failed: %q", items)
	}
	if out["inline"] != "x "+evil+" y" || out["q"] != evil {
		t.Errorf("inline/quote roundtrip failed: %q %q", out["inline"], out["q"])
	}
	if out["crit"].(float64) != 1 || out["sev"].(map[string]any)["HIGH"].(float64) != 1 {
		t.Errorf("countBySeverity: %v %v", out["crit"], out["sev"])
	}
	if out["up"] != "NEW_CRITICAL" || out["low"] != "abc" || out["tr"] != "ab…" || out["def"] != "prod" {
		t.Errorf("string funcs: %v", out)
	}
	if out["first"].(float64) != 1 || out["join"] != "a,b" || out["t"] != "2026-01-02" || out["base"] != "https://k.example" || out["new"] != true {
		t.Errorf("misc funcs: %v", out)
	}
}

func TestInvalidTemplateRejected(t *testing.T) {
	st := newStore(t)
	for name, tmpl := range map[string]string{
		"syntax":      `{"a": {{ .Count }`,
		"unknownFunc": `{"a": {{ env "HOME" }}}`,
		"unknownFld":  `{"a": {{ .Nope }}}`,
		"missingKey":  `{"a": {{ json .Secrets.typo }}}`,
		"invalidJSON": `{"a": {{ (index .Findings 0).Title }}}`,
		"call":        `{"a": {{ call .Count }}}`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.NotificationsConfig{Destinations: []config.WebhookDestination{
				dest("d", "https://example.com", func(d *config.WebhookDestination) {
					d.Template = tmpl
					d.Events = []string{config.EventNewCritical}
				}),
			}}
			if _, err := New(cfg, st, nil); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRenderRejectsInvalidJSONAndSize(t *testing.T) {
	st := newStore(t)
	cfg := config.NotificationsConfig{Destinations: []config.WebhookDestination{
		// Valid for the sample (simple title) but not for a malicious one.
		dest("d", "https://example.com", func(d *config.WebhookDestination) {
			d.Template = `{"t": "{{ (index .Findings 0).PkgName }}"}`
			d.Events = []string{config.EventNewCritical}
		}),
		dest("big", "https://example.com", func(d *config.WebhookDestination) {
			d.Template = `{"x": {{ json (printf "%0*d" (add 10 (len .Findings)) 0) }}, "f": [{{ range $i, $f := .Findings }}{{ if $i }},{{ end }}{{ json $f }}{{ end }}]}`
			d.Events = []string{config.EventNewCritical}
		}),
	}}
	e, err := New(cfg, st, nil, WithRenderLimits(4096, time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Render("d", testEvent(FindingInfo{ID: "x", PkgName: `bad"pkg`, Namespaces: []string{"a"}})); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("want invalid JSON error, got %v", err)
	}
	var many []FindingInfo
	for range 100 {
		many = append(many, FindingInfo{ID: "x", Title: strings.Repeat("y", 100)})
	}
	if _, err := e.Render("big", testEvent(many...)); err == nil || !errors.Is(err, errBodyTooLarge) && !strings.Contains(err.Error(), "exceeds size") {
		t.Fatalf("want size error, got %v", err)
	}
}

func TestDefaultBody(t *testing.T) {
	st := newStore(t)
	cfg := config.NotificationsConfig{Destinations: []config.WebhookDestination{dest("d", "https://example.com")}}
	e, err := New(cfg, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := e.Render("d", testEvent())
	if err != nil {
		t.Fatal(err)
	}
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil || ev.Type != config.EventNewCritical || len(ev.Findings) != 1 {
		t.Fatalf("default body %s: %v", body, err)
	}
}

func TestTemplateTimeout(t *testing.T) {
	st := newStore(t)
	cfg := config.NotificationsConfig{Destinations: []config.WebhookDestination{
		dest("d", "https://example.com", func(d *config.WebhookDestination) {
			d.Template = `{{ $n := 1 }}{{ if gt .Count 1 }}{{ range 2000000000 }}{{ $n = add $n 1 }}{{ end }}{{ end }}{}`
			d.Events = []string{config.EventNewCritical}
		}),
	}}
	e, err := New(cfg, st, nil, WithRenderLimits(DefaultMaxBodyBytes, 50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	two := testEvent(FindingInfo{ID: "a", Namespaces: []string{"x"}}, FindingInfo{ID: "b", Namespaces: []string{"x"}})
	if _, err := e.Render("d", two); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("want timeout, got %v", err)
	}
}

// ---- filtering ----

func TestEventAndNamespaceFilter(t *testing.T) {
	d := &destination{events: map[string]bool{config.EventNewCritical: true, config.EventScanFailed: true},
		nsAllow: map[string]bool{"team-a": true}}
	ev := testEvent(
		FindingInfo{ID: "1", Namespaces: []string{"team-a", "team-b"}, Workloads: []string{"team-a/Deployment/x", "team-b/Deployment/y"}},
		FindingInfo{ID: "2", Namespaces: []string{"team-b"}},
	)
	got, ok := d.filter(ev)
	if !ok || len(got.Findings) != 1 || got.Findings[0].ID != "1" {
		t.Fatalf("filter: %v %+v", ok, got.Findings)
	}
	if strings.Join(got.Findings[0].Namespaces, ",") != "team-a" || strings.Join(got.Findings[0].Workloads, ",") != "team-a/Deployment/x" {
		t.Errorf("other namespaces leaked: %+v", got.Findings[0])
	}
	if len(ev.Findings[0].Namespaces) != 2 {
		t.Error("filter mutated caller's event")
	}
	if _, ok := d.filter(testEvent(FindingInfo{ID: "3", Namespaces: []string{"team-b"}})); ok {
		t.Error("expected skip when nothing left")
	}
	resolved := testEvent()
	resolved.Type = config.EventResolved
	if _, ok := d.filter(resolved); ok {
		t.Error("unsubscribed event type sent")
	}
	failed := Event{Type: config.EventScanFailed, Scan: ScanInfo{ID: "s", Scope: "cluster"}}
	if _, ok := d.filter(failed); !ok {
		t.Error("cluster scan_failed should pass namespace filter")
	}
	failed.Scan.Namespace = "team-b"
	if _, ok := d.filter(failed); ok {
		t.Error("other team's namespace scan_failed should be skipped")
	}
}

func TestNotifyFiltersPerDestination(t *testing.T) {
	var rec recorder
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rec.record(r) }))
	defer srv.Close()
	st := newStore(t)
	cfg := config.NotificationsConfig{AllowPrivateNetworks: true, Destinations: []config.WebhookDestination{
		dest("all", srv.URL),
		dest("failures-only", srv.URL, func(d *config.WebhookDestination) { d.Events = []string{config.EventScanFailed} }),
		dest("team-b", srv.URL, func(d *config.WebhookDestination) { d.Namespaces = []string{"team-b"} }),
	}}
	e := startEngine(t, cfg, st, fastOpts(nil)...)
	if err := e.Notify(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	all := waitFinal(t, st, 1)
	if len(all) != 1 || all[0].Destination != "all" || all[0].Status != store.DeliveryDelivered || all[0].ResponseCode != 200 {
		t.Fatalf("deliveries: %+v", all)
	}
	if rec.calls.Load() != 1 {
		t.Fatalf("calls = %d", rec.calls.Load())
	}
}

// ---- delivery ----

func TestDedupe(t *testing.T) {
	var rec recorder
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rec.record(r) }))
	defer srv.Close()
	st := newStore(t)
	cfg := config.NotificationsConfig{AllowPrivateNetworks: true, Destinations: []config.WebhookDestination{
		dest("d", srv.URL, func(d *config.WebhookDestination) {
			d.Headers = map[string]string{"X-Token": "s3cr3t-value"}
		}),
	}}
	e := startEngine(t, cfg, st, fastOpts(nil)...)
	ev := testEvent(FindingInfo{ID: "b", Namespaces: []string{"x"}}, FindingInfo{ID: "a", Namespaces: []string{"x"}})
	for range 2 {
		if err := e.Notify(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	// Same finding set in a different order is still a duplicate.
	ev.Findings[0], ev.Findings[1] = ev.Findings[1], ev.Findings[0]
	if err := e.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	all := waitFinal(t, st, 1)
	time.Sleep(50 * time.Millisecond)
	if len(all) != 1 || rec.calls.Load() != 1 {
		t.Fatalf("want 1 delivery/call, got %d/%d", len(all), rec.calls.Load())
	}
	if rec.hdrs[0].Get("X-Token") != "s3cr3t-value" || rec.hdrs[0].Get("Content-Type") != "application/json" {
		t.Errorf("headers: %v", rec.hdrs[0])
	}
	// A different scan is a new notification.
	ev.Scan.ID = "scan-2"
	_ = e.Notify(context.Background(), ev)
	waitFinal(t, st, 2)
	if rec.calls.Load() != 2 {
		t.Errorf("calls = %d", rec.calls.Load())
	}
}

func TestRetryOn500ThenSuccess(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	st := newStore(t)
	var sleeps []time.Duration
	cfg := config.NotificationsConfig{AllowPrivateNetworks: true, Destinations: []config.WebhookDestination{dest("d", srv.URL)}}
	e := startEngine(t, cfg, st, fastOpts(&sleeps)...)
	_ = e.Notify(context.Background(), testEvent())
	all := waitFinal(t, st, 1)
	if all[0].Status != store.DeliveryDelivered || all[0].Attempts != 3 || all[0].ResponseCode != 204 || all[0].DeliveredAt == nil {
		t.Fatalf("delivery: %+v", all[0])
	}
	if len(sleeps) != 2 {
		t.Errorf("sleeps: %v", sleeps)
	}
}

func TestRetriesExhausted(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(502)
	}))
	defer srv.Close()
	st := newStore(t)
	cfg := config.NotificationsConfig{AllowPrivateNetworks: true, Destinations: []config.WebhookDestination{
		dest("d", srv.URL, func(d *config.WebhookDestination) { d.MaxRetries = 2 }),
	}}
	e := startEngine(t, cfg, st, fastOpts(nil)...)
	_ = e.Notify(context.Background(), testEvent())
	all := waitFinal(t, st, 1)
	if all[0].Status != store.DeliveryFailed || all[0].Attempts != 3 || n.Load() != 3 || all[0].ResponseCode != 502 {
		t.Fatalf("delivery: %+v (calls %d)", all[0], n.Load())
	}
}

func TestNoRetryOn400AndSecretsRedacted(t *testing.T) {
	var n atomic.Int32
	const token = "123456:ABCDEFsecretTOKEN"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(400)
		// A misbehaving server echoing credentials back.
		_, _ = io.WriteString(w, `{"error":"bad request for bot`+token+` with header hdr-secret-val chat chat-secret-1"}`)
	}))
	defer srv.Close()
	st := newStore(t)
	cfg := config.NotificationsConfig{AllowPrivateNetworks: true, Destinations: []config.WebhookDestination{
		dest("d", srv.URL+"/bot"+token+"/sendMessage", func(d *config.WebhookDestination) {
			d.Headers = map[string]string{"Authorization": "Bearer hdr-secret-val"}
			d.Secrets = map[string]string{"chat": "chat-secret-1"}
		}),
	}}
	e := startEngine(t, cfg, st, fastOpts(nil)...)
	_ = e.Notify(context.Background(), testEvent())
	all := waitFinal(t, st, 1)
	d := all[0]
	if d.Status != store.DeliveryFailed || d.Attempts != 1 || n.Load() != 1 || d.ResponseCode != 400 {
		t.Fatalf("delivery: %+v", d)
	}
	for _, s := range []string{token, "hdr-secret-val", "chat-secret-1"} {
		if strings.Contains(d.LastError, s) {
			t.Errorf("LastError leaks %q: %s", s, d.LastError)
		}
	}
	if !strings.Contains(d.LastError, "HTTP 400") {
		t.Errorf("LastError: %s", d.LastError)
	}
}

func TestRetryAfter(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(429)
		case 2:
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(429)
		default:
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	st := newStore(t)
	var sleeps []time.Duration
	cfg := config.NotificationsConfig{AllowPrivateNetworks: true, Destinations: []config.WebhookDestination{dest("d", srv.URL)}}
	opts := append(fastOpts(&sleeps), WithRetryAfterCap(30*time.Second))
	e := startEngine(t, cfg, st, opts...)
	_ = e.Notify(context.Background(), testEvent())
	all := waitFinal(t, st, 1)
	if all[0].Status != store.DeliveryDelivered || all[0].Attempts != 3 {
		t.Fatalf("delivery: %+v", all[0])
	}
	if len(sleeps) != 2 || sleeps[0] != 7*time.Second || sleeps[1] != 30*time.Second {
		t.Errorf("sleeps: %v", sleeps)
	}
	if got := parseRetryAfter(time.Now().Add(time.Minute).UTC().Format(http.TimeFormat), time.Now()); got < 58*time.Second || got > time.Minute {
		t.Errorf("http-date Retry-After: %v", got)
	}
}

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	st := newStore(t)
	cfg := config.NotificationsConfig{AllowPrivateNetworks: true, Destinations: []config.WebhookDestination{
		dest("d", srv.URL, func(d *config.WebhookDestination) {
			d.Timeout.Duration = 100 * time.Millisecond
			d.MaxRetries = 1
		}),
	}}
	e := startEngine(t, cfg, st, fastOpts(nil)...)
	_ = e.Notify(context.Background(), testEvent())
	all := waitFinal(t, st, 1)
	if all[0].Status != store.DeliveryFailed || all[0].Attempts != 2 || !strings.Contains(all[0].LastError, "timeout") {
		t.Fatalf("delivery: %+v", all[0])
	}
}

func TestNoRedirects(t *testing.T) {
	var hit atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Add(1) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	st := newStore(t)
	cfg := config.NotificationsConfig{AllowPrivateNetworks: true, Destinations: []config.WebhookDestination{dest("d", srv.URL)}}
	e := startEngine(t, cfg, st, fastOpts(nil)...)
	_ = e.Notify(context.Background(), testEvent())
	all := waitFinal(t, st, 1)
	if all[0].Status != store.DeliveryFailed || all[0].Attempts != 1 || all[0].ResponseCode != 307 || hit.Load() != 0 {
		t.Fatalf("delivery: %+v hit=%d", all[0], hit.Load())
	}
}

func TestSSRFBlockedEndToEnd(t *testing.T) {
	var hit atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Add(1) }))
	defer srv.Close()
	st := newStore(t)
	// Default client with dial guard; hostname "localhost" exercises resolution.
	url := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	cfg := config.NotificationsConfig{Destinations: []config.WebhookDestination{dest("d", url)}}
	e := startEngine(t, cfg, st, fastOpts(nil)...)
	_ = e.Notify(context.Background(), testEvent())
	all := waitFinal(t, st, 1)
	if all[0].Status != store.DeliveryFailed || all[0].Attempts != 1 || !strings.Contains(all[0].LastError, "blocked") || hit.Load() != 0 {
		t.Fatalf("delivery: %+v hit=%d", all[0], hit.Load())
	}
}

func TestCheckIP(t *testing.T) {
	blocked := []string{"127.0.0.1", "127.1.2.3", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "::", "fe80::1", "fc00::1", "fd12::1",
		"ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a00:1", "2002:a00:1::1", "::10.0.0.1"}
	for _, s := range blocked {
		if CheckIP(netip.MustParseAddr(s)) == nil {
			t.Errorf("%s should be blocked", s)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "149.154.167.220", "2606:4700:4700::1111", "64:ff9b::808:808"}
	for _, s := range allowed {
		if err := CheckIP(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s should be allowed: %v", s, err)
		}
	}
	ctl := ssrfControl(CheckIP)
	if err := ctl("tcp4", "169.254.169.254:80", nil); err == nil {
		t.Error("control should block metadata IP")
	}
	if err := ctl("tcp6", "[fe80::1%en0]:443", nil); err == nil {
		t.Error("control should block zoned link-local")
	}
	if err := ctl("tcp4", "93.184.215.14:443", nil); err != nil {
		t.Errorf("control blocked public IP: %v", err)
	}
}

// ---- lifecycle ----

func TestQueueFullAndClose(t *testing.T) {
	st := newStore(t)
	cfg := config.NotificationsConfig{AllowPrivateNetworks: true, Destinations: []config.WebhookDestination{dest("d", "http://127.0.0.1:1")}}
	e, err := New(cfg, st, nil, WithQueueSize(1))
	if err != nil {
		t.Fatal(err)
	}
	// Not started: first fills the queue, second overflows.
	ev := testEvent()
	_ = e.Notify(context.Background(), ev)
	ev.Scan.ID = "scan-2"
	_ = e.Notify(context.Background(), ev)
	_ = e.Close()
	ev.Scan.ID = "scan-3"
	_ = e.Notify(context.Background(), ev)
	all, _ := st.ListDeliveries(context.Background(), "", 10)
	reasons := map[string]bool{}
	for _, d := range all {
		if d.Status != store.DeliveryFailed {
			t.Errorf("want failed: %+v", d)
		}
		reasons[d.LastError] = true
	}
	for _, r := range []string{"notification queue full", "interrupted by shutdown", "notifier closed"} {
		if !reasons[r] {
			t.Errorf("missing reason %q in %v", r, reasons)
		}
	}
	if e.Close() != nil {
		t.Error("second Close should be a no-op")
	}
}

func TestStartMarksStalePendingFailed(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	old := time.Now().Add(-time.Hour).UTC()
	stale := &store.NotificationDelivery{ID: newID(), Destination: "d", Event: "new_critical", DedupKey: "k1", Status: store.DeliveryPending, CreatedAt: old}
	fresh := &store.NotificationDelivery{ID: newID(), Destination: "d", Event: "new_critical", DedupKey: "k2", Status: store.DeliveryPending, CreatedAt: time.Now().UTC()}
	for _, d := range []*store.NotificationDelivery{stale, fresh} {
		if err := st.CreateDelivery(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	startEngine(t, config.NotificationsConfig{}, st)
	failed, _ := st.ListDeliveries(ctx, store.DeliveryFailed, 10)
	if len(failed) != 1 || failed[0].ID != stale.ID || failed[0].LastError != "interrupted by restart" {
		t.Fatalf("failed: %+v", failed)
	}
}

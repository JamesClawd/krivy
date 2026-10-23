package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/l4r-s/krivy/internal/auth"
	"github.com/l4r-s/krivy/internal/config"
	"github.com/l4r-s/krivy/internal/service"
	"github.com/l4r-s/krivy/internal/store"
)

// fakeService records calls and does NOT enforce scopes, so the tests
// prove the transport pre-check works on its own.
type fakeService struct {
	mu          sync.Mutex
	calls       []string
	lastScan    service.ScanRequest
	lastTrigger string
	lastScanF   store.ScanRunFilter
	lastFindF   store.FindingFilter
	lastAck     service.AckRequest
	lastSilence service.SilenceRequest
	lastAll     bool
	err         error // returned by every method when set
}

func (f *fakeService) rec(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	return f.err
}

func (f *fakeService) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

var now = time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC)

func (f *fakeService) TriggerScan(_ context.Context, req service.ScanRequest, trigger string) (*store.ScanRun, error) {
	if err := f.rec("TriggerScan"); err != nil {
		return nil, err
	}
	f.lastScan, f.lastTrigger = req, trigger
	return &store.ScanRun{ID: "run-1", Scope: req.Scope, Namespace: req.Namespace, Trigger: trigger, Status: store.StatusPending, CreatedAt: now}, nil
}
func (f *fakeService) GetScan(_ context.Context, id string) (*service.ScanStatus, error) {
	if err := f.rec("GetScan"); err != nil {
		return nil, err
	}
	return &service.ScanStatus{ScanRun: store.ScanRun{ID: id, Status: store.StatusRunning}, Jobs: []store.ScanJob{{ID: "job-1", ScanRunID: id}}}, nil
}
func (f *fakeService) ListScans(_ context.Context, fl store.ScanRunFilter) ([]store.ScanRun, int64, error) {
	if err := f.rec("ListScans"); err != nil {
		return nil, 0, err
	}
	f.lastScanF = fl
	return []store.ScanRun{{ID: "run-1"}}, 7, nil
}
func (f *fakeService) CancelScan(_ context.Context, id string) (*store.ScanRun, error) {
	if err := f.rec("CancelScan"); err != nil {
		return nil, err
	}
	return &store.ScanRun{ID: id, CancelRequested: true}, nil
}
func (f *fakeService) ListFindings(_ context.Context, fl store.FindingFilter) ([]store.Finding, int64, error) {
	if err := f.rec("ListFindings"); err != nil {
		return nil, 0, err
	}
	f.lastFindF = fl
	return nil, 0, nil
}
func (f *fakeService) GetFinding(_ context.Context, id string) (*service.FindingDetail, error) {
	if err := f.rec("GetFinding"); err != nil {
		return nil, err
	}
	return &service.FindingDetail{Finding: store.Finding{ID: id}, Workloads: []store.Workload{}, Namespaces: []string{}}, nil
}
func (f *fakeService) Acknowledge(_ context.Context, id string, req service.AckRequest) (*store.Finding, error) {
	if err := f.rec("Acknowledge"); err != nil {
		return nil, err
	}
	f.lastAck = req
	return &store.Finding{ID: id, AcknowledgedAt: &now, AckReason: req.Reason}, nil
}
func (f *fakeService) Unacknowledge(_ context.Context, id string) (*store.Finding, error) {
	if err := f.rec("Unacknowledge"); err != nil {
		return nil, err
	}
	return &store.Finding{ID: id}, nil
}
func (f *fakeService) CreateSilence(_ context.Context, req service.SilenceRequest) (*store.Silence, error) {
	if err := f.rec("CreateSilence"); err != nil {
		return nil, err
	}
	f.lastSilence = req
	return &store.Silence{ID: "sil-1", Kind: req.Kind, Target: req.Target}, nil
}
func (f *fakeService) ListSilences(_ context.Context, includeInactive bool) ([]store.Silence, error) {
	if err := f.rec("ListSilences"); err != nil {
		return nil, err
	}
	f.lastAll = includeInactive
	return nil, nil
}
func (f *fakeService) RevokeSilence(_ context.Context, id string) (*store.Silence, error) {
	if err := f.rec("RevokeSilence"); err != nil {
		return nil, err
	}
	return &store.Silence{ID: id, RevokedAt: &now}, nil
}
func (f *fakeService) Summary(_ context.Context) (*store.Summary, error) {
	if err := f.rec("Summary"); err != nil {
		return nil, err
	}
	return &store.Summary{OpenFindings: 3}, nil
}

var _ service.API = (*fakeService)(nil)

const (
	readTok   = "read-token"
	scanTok   = "scan-token"
	manageTok = "manage-token"
)

func newTestServer(t *testing.T) (*httptest.Server, *fakeService, *bytes.Buffer) {
	t.Helper()
	a, err := auth.New([]config.TokenConfig{
		{Name: "reader", Token: readTok, Scopes: []config.Scope{config.ScopeRead}},
		{Name: "scanner", Token: scanTok, Scopes: []config.Scope{config.ScopeScan}},
		{Name: "admin", Token: manageTok, Scopes: []config.Scope{config.ScopeManage}},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := &fakeService{}
	logs := &bytes.Buffer{}
	srv := httptest.NewServer(New(svc, a, slog.New(slog.NewTextHandler(logs, nil))))
	t.Cleanup(srv.Close)
	return srv, svc, logs
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func do(t *testing.T, srv *httptest.Server, method, path, token, body string) resp {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, b}
}

func errCode(t *testing.T, r resp) string {
	t.Helper()
	var e errorBody
	if err := json.Unmarshal(r.body, &e); err != nil {
		t.Fatalf("error body not JSON: %q", r.body)
	}
	if e.Error.Message == "" {
		t.Errorf("empty error message: %s", r.body)
	}
	return e.Error.Code
}

func TestAuthentication(t *testing.T) {
	srv, svc, _ := newTestServer(t)
	for _, tok := range []string{"", "wrong"} {
		r := do(t, srv, "GET", "/api/v1/summary", tok, "")
		if r.status != 401 || errCode(t, r) != "unauthenticated" {
			t.Errorf("token %q: got %d %s", tok, r.status, r.body)
		}
		if r.header.Get("WWW-Authenticate") == "" {
			t.Error("missing WWW-Authenticate")
		}
		if ct := r.header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type %q", ct)
		}
	}
	if len(svc.called()) != 0 {
		t.Errorf("service reached without auth: %v", svc.called())
	}
}

func TestScopeMatrix(t *testing.T) {
	type tc struct {
		method, path, body string
		want               map[string]int // token -> status
	}
	ok := func(read, scan, manage int) map[string]int {
		return map[string]int{readTok: read, scanTok: scan, manageTok: manage}
	}
	cases := []tc{
		{"GET", "/api/v1/summary", "", ok(200, 200, 200)},
		{"GET", "/api/v1/scans", "", ok(200, 200, 200)},
		{"GET", "/api/v1/scans/run-1", "", ok(200, 200, 200)},
		{"GET", "/api/v1/findings", "", ok(200, 200, 200)},
		{"GET", "/api/v1/findings/f1", "", ok(200, 200, 200)},
		{"GET", "/api/v1/silences", "", ok(200, 200, 200)},
		{"POST", "/api/v1/scans", `{"scope":"cluster"}`, ok(403, 202, 202)},
		{"POST", "/api/v1/scans/run-1/cancel", "", ok(403, 200, 200)},
		{"POST", "/api/v1/findings/f1/acknowledge", `{"reason":"x"}`, ok(403, 403, 200)},
		{"DELETE", "/api/v1/findings/f1/acknowledge", "", ok(403, 403, 200)},
		{"POST", "/api/v1/silences", `{"kind":"vulnerability","target":"CVE-1"}`, ok(403, 403, 201)},
		{"DELETE", "/api/v1/silences/sil-1", "", ok(403, 403, 200)},
	}
	for _, c := range cases {
		for tok, want := range c.want {
			srv, svc, _ := newTestServer(t)
			r := do(t, srv, c.method, c.path, tok, c.body)
			if r.status != want {
				t.Errorf("%s %s with %s: got %d want %d (%s)", c.method, c.path, tok, r.status, want, r.body)
				continue
			}
			if want == 403 {
				if errCode(t, r) != "forbidden" {
					t.Errorf("%s %s: wrong code %s", c.method, c.path, r.body)
				}
				if n := len(svc.called()); n != 0 {
					t.Errorf("%s %s with %s: service reached despite 403: %v", c.method, c.path, tok, svc.called())
				}
			}
		}
	}
}

func TestTriggerScan(t *testing.T) {
	srv, svc, _ := newTestServer(t)
	r := do(t, srv, "POST", "/api/v1/scans", scanTok, `{"scope":"namespace","namespace":"payments"}`)
	if r.status != 202 {
		t.Fatalf("status %d %s", r.status, r.body)
	}
	if loc := r.header.Get("Location"); loc != "/api/v1/scans/run-1" {
		t.Errorf("Location %q", loc)
	}
	if svc.lastTrigger != store.TriggerAPI || svc.lastScan.Namespace != "payments" || svc.lastScan.Scope != "namespace" {
		t.Errorf("unexpected call: %+v %q", svc.lastScan, svc.lastTrigger)
	}
	var run store.ScanRun
	if err := json.Unmarshal(r.body, &run); err != nil || run.ID != "run-1" {
		t.Errorf("body %s", r.body)
	}

	// Empty body defaults to a cluster scan.
	r = do(t, srv, "POST", "/api/v1/scans", scanTok, "")
	if r.status != 202 || svc.lastScan.Scope != store.ScopeCluster {
		t.Errorf("empty body: %d %+v", r.status, svc.lastScan)
	}
}

func TestBodyValidation(t *testing.T) {
	srv, svc, _ := newTestServer(t)
	cases := []struct{ path, body string }{
		{"/api/v1/scans", `{"scope":"cluster","bogus":1}`},
		{"/api/v1/scans", `{not json`},
		{"/api/v1/scans", `{"scope":"cluster"}{"scope":"cluster"}`},
		{"/api/v1/silences", ``},
		{"/api/v1/silences", `{"kind":"image","target":"x","expiresAt":"tomorrow"}`},
		{"/api/v1/silences", `{"kind":"image","target":"` + strings.Repeat("a", MaxBodyBytes) + `"}`},
	}
	for _, c := range cases {
		r := do(t, srv, "POST", c.path, manageTok, c.body)
		if r.status != 400 || errCode(t, r) != "bad_request" {
			name := c.body
			if len(name) > 40 {
				name = name[:40]
			}
			t.Errorf("POST %s %q: got %d %.200s", c.path, name, r.status, r.body)
		}
	}
	if len(svc.called()) != 0 {
		t.Errorf("service called on invalid input: %v", svc.called())
	}
}

func TestSilenceCreate(t *testing.T) {
	srv, svc, _ := newTestServer(t)
	r := do(t, srv, "POST", "/api/v1/silences", manageTok,
		`{"kind":"vulnerability","target":"CVE-2024-3094","reason":"accepted","expiresAt":"2026-12-31T00:00:00Z"}`)
	if r.status != 201 {
		t.Fatalf("status %d %s", r.status, r.body)
	}
	if svc.lastSilence.ExpiresAt == nil || svc.lastSilence.Reason != "accepted" {
		t.Errorf("request not passed: %+v", svc.lastSilence)
	}
	r = do(t, srv, "GET", "/api/v1/silences?all=true", readTok, "")
	if r.status != 200 || !svc.lastAll {
		t.Errorf("all=true not honored: %d", r.status)
	}
	var l List[store.Silence]
	if err := json.Unmarshal(r.body, &l); err != nil || l.Items == nil {
		t.Errorf("items should be [] not null: %s", r.body)
	}
	if r := do(t, srv, "GET", "/api/v1/silences?all=maybe", readTok, ""); r.status != 400 {
		t.Errorf("all=maybe: %d", r.status)
	}
}

func TestPagination(t *testing.T) {
	srv, svc, _ := newTestServer(t)
	r := do(t, srv, "GET", "/api/v1/scans?limit=10&offset=20&status=running&scope=namespace&namespace=ns", readTok, "")
	if r.status != 200 {
		t.Fatalf("status %d %s", r.status, r.body)
	}
	f := svc.lastScanF
	if f.Limit != 10 || f.Offset != 20 || f.Status != "running" || f.Scope != "namespace" || f.Namespace != "ns" {
		t.Errorf("filter %+v", f)
	}
	var p Page[store.ScanRun]
	if err := json.Unmarshal(r.body, &p); err != nil {
		t.Fatal(err)
	}
	if p.Total != 7 || p.Limit != 10 || p.Offset != 20 || len(p.Items) != 1 {
		t.Errorf("page %+v", p)
	}

	r = do(t, srv, "GET", "/api/v1/findings", readTok, "")
	if svc.lastFindF.Limit != DefaultLimit || svc.lastFindF.Offset != 0 {
		t.Errorf("defaults %+v", svc.lastFindF.Page)
	}
	if !bytes.Contains(r.body, []byte(`"items":[]`)) {
		t.Errorf("empty items should be []: %s", r.body)
	}

	r = do(t, srv, "GET", "/api/v1/findings?status=open&severity=critical&namespace=a&image=img&vulnerability=CVE-1&acknowledged=false&deployed=true&limit=500", readTok, "")
	ff := svc.lastFindF
	if r.status != 200 || ff.Status != "open" || ff.Severity != "CRITICAL" || ff.Namespace != "a" || ff.ImageKey != "img" ||
		ff.VulnerabilityID != "CVE-1" || ff.Acknowledged == nil || *ff.Acknowledged || ff.Deployed == nil || !*ff.Deployed || ff.Limit != 500 {
		t.Errorf("finding filter %d %+v", r.status, ff)
	}

	for _, q := range []string{
		"limit=0", "limit=501", "limit=abc", "offset=-1", "offset=x",
		"status=bogus", "severity=bad", "acknowledged=yes", "deployed=1",
	} {
		r := do(t, srv, "GET", "/api/v1/findings?"+q, readTok, "")
		if r.status != 400 || errCode(t, r) != "bad_request" {
			t.Errorf("%s: got %d", q, r.status)
		}
	}
	if r := do(t, srv, "GET", "/api/v1/scans?scope=everything", readTok, ""); r.status != 400 {
		t.Errorf("bad scope: %d", r.status)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{store.ErrNotFound, 404, "not_found"},
		{fmt.Errorf("get: %w", store.ErrNotFound), 404, "not_found"},
		{fmt.Errorf("%w: namespace required", service.ErrInvalid), 400, "bad_request"},
		{fmt.Errorf("%w: already finished", service.ErrConflict), 409, "conflict"},
		{auth.ErrForbidden, 403, "forbidden"},
		{auth.ErrUnauthenticated, 401, "unauthenticated"},
		{errors.New("db exploded: secret dsn"), 500, "internal"},
	}
	for _, c := range cases {
		srv, svc, logs := newTestServer(t)
		svc.err = c.err
		r := do(t, srv, "POST", "/api/v1/scans/run-1/cancel", manageTok, "")
		if r.status != c.status || errCode(t, r) != c.code {
			t.Errorf("%v: got %d %s", c.err, r.status, r.body)
		}
		if c.status == 500 {
			if bytes.Contains(r.body, []byte("secret")) {
				t.Errorf("internal error leaked: %s", r.body)
			}
			if !strings.Contains(logs.String(), "db exploded") {
				t.Errorf("internal error not logged: %q", logs.String())
			}
		}
		if strings.Contains(logs.String(), manageTok) {
			t.Error("token leaked into logs")
		}
	}
}

func TestNotFoundAndMethod(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := do(t, srv, "GET", "/api/v1/nope", readTok, "")
	if r.status != 404 || errCode(t, r) != "not_found" {
		t.Errorf("unknown path: %d %s", r.status, r.body)
	}
	r = do(t, srv, "PUT", "/api/v1/scans", manageTok, "")
	if r.status != 405 || errCode(t, r) != "method_not_allowed" || !strings.Contains(r.header.Get("Allow"), "POST") {
		t.Errorf("wrong method: %d %v %s", r.status, r.header, r.body)
	}
}

func TestOpenAPI(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := do(t, srv, "GET", "/api/v1/openapi.yaml", "", "")
	if r.status != 200 {
		t.Fatalf("status %d", r.status)
	}
	var doc struct {
		OpenAPI    string                               `json:"openapi"`
		Paths      map[string]map[string]map[string]any `json:"paths"`
		Components struct {
			SecuritySchemes map[string]any `json:"securitySchemes"`
			Schemas         map[string]any `json:"schemas"`
		} `json:"components"`
	}
	var generic map[string]any
	if err := yaml.UnmarshalStrict(r.body, &generic); err != nil { // rejects duplicate keys
		t.Fatalf("spec does not parse: %v", err)
	}
	if err := yaml.Unmarshal(r.body, &doc); err != nil {
		t.Fatalf("spec does not parse: %v", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.1") {
		t.Errorf("openapi version %q", doc.OpenAPI)
	}
	if _, ok := doc.Components.SecuritySchemes["bearerAuth"]; !ok {
		t.Error("bearerAuth scheme missing")
	}
	if _, ok := doc.Components.Schemas["Error"]; !ok {
		t.Error("Error schema missing")
	}

	registered := map[string]bool{}
	for _, rt := range routeTable() {
		key := strings.ToLower(rt.Method) + " " + rt.Path
		registered[key] = true
		ops, ok := doc.Paths[rt.Path]
		if !ok {
			t.Errorf("route %s %s missing from spec", rt.Method, rt.Path)
			continue
		}
		op, ok := ops[strings.ToLower(rt.Method)]
		if !ok {
			t.Errorf("method %s missing for %s in spec", rt.Method, rt.Path)
			continue
		}
		// Unauthenticated routes must declare security: [] in the spec,
		// authenticated ones must not opt out.
		sec, hasSec := op["security"]
		public := hasSec && fmt.Sprint(sec) == "[]"
		if public != (rt.Scope == "") {
			t.Errorf("%s %s: spec security %v does not match route scope %q", rt.Method, rt.Path, sec, rt.Scope)
		}
	}
	// And the reverse: the spec documents nothing that is not served.
	for path, ops := range doc.Paths {
		for method := range ops {
			if method == "parameters" {
				continue
			}
			if !registered[method+" "+path] {
				t.Errorf("spec documents %s %s which is not registered", method, path)
			}
		}
	}
	// Every $ref must resolve.
	for _, m := range refRe(r.body) {
		name := strings.TrimPrefix(m, "#/components/")
		parts := strings.SplitN(name, "/", 2)
		if !bytes.Contains(r.body, []byte("\n    "+parts[1]+":")) {
			t.Errorf("unresolved $ref %s", m)
		}
	}
}

func refRe(b []byte) []string {
	var out []string
	s := string(b)
	for {
		i := strings.Index(s, "$ref: '")
		if i < 0 {
			return out
		}
		s = s[i+len("$ref: '"):]
		j := strings.IndexByte(s, '\'')
		out = append(out, s[:j])
		s = s[j:]
	}
}

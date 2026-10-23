package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/l4r-s/krivy/internal/auth"
	"github.com/l4r-s/krivy/internal/config"
	"github.com/l4r-s/krivy/internal/service"
	"github.com/l4r-s/krivy/internal/store"
)

// fakeService embeds the interface (unimplemented methods panic) and, like
// the real service, enforces scopes from the context principal, which
// proves the principal reaches the service through the MCP layer.
type fakeService struct {
	service.API
	mu          sync.Mutex
	calls       []string
	lastTrigger string
	lastActor   string
}

func (f *fakeService) rec(ctx context.Context, name string, s config.Scope) error {
	p, err := auth.Require(ctx, s)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	if p != nil {
		f.lastActor = p.Actor()
	}
	return err
}

func (f *fakeService) Summary(ctx context.Context) (*store.Summary, error) {
	if err := f.rec(ctx, "Summary", config.ScopeRead); err != nil {
		return nil, err
	}
	return &store.Summary{OpenFindings: 5, OpenBySeverity: map[string]int64{"CRITICAL": 2, "HIGH": 3}}, nil
}

func (f *fakeService) ListFindings(ctx context.Context, fl store.FindingFilter) ([]store.Finding, int64, error) {
	if err := f.rec(ctx, "ListFindings", config.ScopeRead); err != nil {
		return nil, 0, err
	}
	return []store.Finding{{ID: "f1", VulnerabilityID: "CVE-2024-3094", Severity: "CRITICAL", Status: "open"}}, 1, nil
}

func (f *fakeService) GetFinding(ctx context.Context, id string) (*service.FindingDetail, error) {
	if err := f.rec(ctx, "GetFinding", config.ScopeRead); err != nil {
		return nil, err
	}
	return nil, store.ErrNotFound
}

func (f *fakeService) Acknowledge(ctx context.Context, id string, req service.AckRequest) (*store.Finding, error) {
	if err := f.rec(ctx, "Acknowledge", config.ScopeManage); err != nil {
		return nil, err
	}
	return &store.Finding{ID: id, AckReason: req.Reason}, nil
}

func (f *fakeService) TriggerScan(ctx context.Context, req service.ScanRequest, trigger string) (*store.ScanRun, error) {
	if err := f.rec(ctx, "TriggerScan", config.ScopeScan); err != nil {
		return nil, err
	}
	f.lastTrigger = trigger
	return &store.ScanRun{ID: "run-1", Scope: req.Scope, Namespace: req.Namespace, Trigger: trigger, Status: store.StatusPending}, nil
}

func (f *fakeService) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

const (
	readTok   = "read-token"
	scanTok   = "scan-token"
	manageTok = "manage-token"
)

func newServer(t *testing.T) (*httptest.Server, *fakeService) {
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
	mux := http.NewServeMux()
	mux.Handle(Path, New(svc, a, "test"))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, svc
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func connect(t *testing.T, srv *httptest.Server, token string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0"}, nil)
	tr := &mcp.StreamableClientTransport{
		Endpoint:             srv.URL + Path,
		HTTPClient:           &http.Client{Transport: bearer{token, http.DefaultTransport}},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}
	cs, err := client.Connect(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func resultText(r *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestListTools(t *testing.T) {
	srv, _ := newServer(t)
	cs := connect(t, srv, readTok)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"scan_cluster": false, "scan_namespace": false, "get_scan_status": true, "list_scans": true,
		"list_findings": true, "get_finding": true, "acknowledge_finding": false, "unacknowledge_finding": false,
		"create_silence": false, "list_silences": true, "remove_silence": false, "security_summary": true,
	}
	got := map[string]*mcp.Tool{}
	for _, tl := range res.Tools {
		got[tl.Name] = tl
	}
	for name, ro := range want {
		tl, ok := got[name]
		if !ok {
			t.Errorf("tool %s missing", name)
			continue
		}
		if tl.Annotations == nil || tl.Annotations.ReadOnlyHint != ro {
			t.Errorf("tool %s: readOnlyHint should be %v", name, ro)
		}
		if tl.OutputSchema == nil {
			t.Errorf("tool %s has no output schema", name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected tool count %d", len(got))
	}
}

func TestReadTool(t *testing.T) {
	srv, svc := newServer(t)
	cs := connect(t, srv, readTok)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "security_summary"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", resultText(res))
	}
	if !strings.Contains(resultText(res), "5 open findings") {
		t.Errorf("text %q", resultText(res))
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out summaryOutput
	if err := json.Unmarshal(raw, &out); err != nil || out.Summary.OpenFindings != 5 {
		t.Errorf("structured %s", raw)
	}
	if svc.lastActor != "token:reader" {
		t.Errorf("principal did not reach service: %q", svc.lastActor)
	}

	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_findings",
		Arguments: map[string]any{"severity": "critical", "limit": 10}})
	if err != nil || res.IsError {
		t.Fatalf("list_findings: %v %s", err, resultText(res))
	}
	if !strings.Contains(resultText(res), "CVE-2024-3094") {
		t.Errorf("text %q", resultText(res))
	}

	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_findings",
		Arguments: map[string]any{"limit": 1000}})
	if err != nil || !res.IsError || !strings.Contains(resultText(res), "limit") {
		t.Errorf("limit validation: %v %+v", err, res)
	}

	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_finding", Arguments: map[string]any{"id": "nope"}})
	if err != nil || !res.IsError || !strings.Contains(resultText(res), "not found") {
		t.Errorf("not found mapping: %v %s", err, resultText(res))
	}
}

func TestForbiddenMutatingTool(t *testing.T) {
	srv, svc := newServer(t)
	cs := connect(t, srv, readTok)
	for _, call := range []mcp.CallToolParams{
		{Name: "acknowledge_finding", Arguments: map[string]any{"id": "f1", "reason": "x"}},
		{Name: "scan_cluster"},
	} {
		res, err := cs.CallTool(context.Background(), &call)
		if err != nil {
			t.Fatalf("%s: transport error %v (want tool error)", call.Name, err)
		}
		if !res.IsError || !strings.Contains(resultText(res), "permission denied") {
			t.Errorf("%s: want permission error, got %+v %q", call.Name, res, resultText(res))
		}
	}
	if c := svc.called(); len(c) != 0 {
		t.Errorf("service reached despite pre-check: %v", c)
	}
}

func TestScanAndManageTokens(t *testing.T) {
	srv, svc := newServer(t)
	cs := connect(t, srv, scanTok)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "scan_namespace", Arguments: map[string]any{"namespace": "payments"}})
	if err != nil || res.IsError {
		t.Fatalf("scan_namespace: %v %s", err, resultText(res))
	}
	if svc.lastTrigger != store.TriggerMCP {
		t.Errorf("trigger %q", svc.lastTrigger)
	}
	res, _ = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "acknowledge_finding", Arguments: map[string]any{"id": "f1"}})
	if !res.IsError {
		t.Error("scan token must not acknowledge")
	}

	cs2 := connect(t, srv, manageTok)
	res, err = cs2.CallTool(context.Background(), &mcp.CallToolParams{Name: "acknowledge_finding", Arguments: map[string]any{"id": "f1", "reason": "ok"}})
	if err != nil || res.IsError {
		t.Fatalf("manage acknowledge: %v %s", err, resultText(res))
	}
}

func TestUnauthenticated(t *testing.T) {
	srv, _ := newServer(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`
	for _, tok := range []string{"", "bogus"} {
		req, _ := http.NewRequest("POST", srv.URL+Path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("token %q: status %d", tok, res.StatusCode)
		}
		if wa := res.Header.Get("WWW-Authenticate"); strings.Contains(wa, "resource_metadata") {
			t.Errorf("OAuth discovery advertised: %q", wa)
		}
	}
	// No OAuth metadata endpoints are served.
	res, err := http.Get(srv.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("oauth metadata status %d", res.StatusCode)
	}

	// The SDK client surfaces the 401 as a connect error.
	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "v0"}, nil)
	_, err = client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: srv.URL + Path, MaxRetries: -1}, nil)
	if err == nil {
		t.Error("connect without token should fail")
	}
}

func TestSessionBoundToToken(t *testing.T) {
	srv, _ := newServer(t)
	cs := connect(t, srv, readTok)
	sid := cs.ID()
	if sid == "" {
		t.Skip("no session id")
	}
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/list"}`
	req, _ := http.NewRequest("POST", srv.URL+Path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", sid)
	req.Header.Set("Authorization", "Bearer "+manageTok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("hijacked session: status %d", res.StatusCode)
	}
}

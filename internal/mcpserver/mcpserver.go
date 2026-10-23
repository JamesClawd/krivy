// Package mcpserver exposes Krivy's service layer as Model Context Protocol
// tools over Streamable HTTP, authenticated with static bearer tokens.
//
// Authentication: every HTTP request must carry "Authorization: Bearer
// <token>"; missing/invalid tokens get a plain 401 without any OAuth
// discovery metadata. The verified principal is attached to the SDK's
// TokenInfo (the SDK's supported hook for passing auth data to tool
// handlers, which run on the session context rather than the HTTP request
// context) and re-installed into the context before the service is called.
// TokenInfo.UserID also binds MCP sessions to the token that opened them.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/l4r-s/krivy/internal/auth"
	"github.com/l4r-s/krivy/internal/config"
	"github.com/l4r-s/krivy/internal/service"
	"github.com/l4r-s/krivy/internal/store"
)

// Path is where the integrator should mount the handler.
const Path = "/mcp"

const (
	maxBodyBytes   = 1 << 20
	sessionTimeout = 30 * time.Minute
	defaultLimit   = 50
	maxLimit       = 500
	principalKey   = "krivy.principal"
)

const instructions = `Krivy scans the container images running in a Kubernetes cluster for known vulnerabilities (CVEs).
Use security_summary for an overview, list_findings/get_finding to inspect vulnerabilities, scan_cluster/scan_namespace to trigger scans (poll get_scan_status), and acknowledge_finding/create_silence to triage.
Silences suppress notifications only; findings stay visible. Tools that change state require a token with the scan or manage scope.`

// New returns an http.Handler serving the MCP Streamable HTTP transport.
// Mount it at Path ("/mcp"); it ignores the request path itself.
func New(svc service.API, a *auth.Authenticator, version string) http.Handler {
	if version == "" {
		version = "dev"
	}
	s := &server{svc: svc, log: slog.Default().With("component", "mcp")}
	srv := mcp.NewServer(&mcp.Implementation{Name: "krivy", Title: "Krivy", Version: version},
		&mcp.ServerOptions{Instructions: instructions})
	s.register(srv)

	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{
			SessionTimeout:      sessionTimeout,
			MaxRequestBodyBytes: maxBodyBytes,
		})

	verifier := func(_ context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
		p, err := a.Verify(token)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", sdkauth.ErrInvalidToken, err)
		}
		scopes := make([]string, 0, len(p.Scopes))
		for sc, ok := range p.Scopes {
			if ok {
				scopes = append(scopes, string(sc))
			}
		}
		return &sdkauth.TokenInfo{
			UserID: p.Actor(),
			Scopes: scopes,
			Extra:  map[string]any{principalKey: p},
		}, nil
	}
	// No ResourceMetadataURL: no OAuth protected-resource discovery is
	// advertised. a.Middleware answers unauthenticated requests first with
	// Krivy's JSON 401; the SDK middleware then attaches the TokenInfo.
	withTokenInfo := sdkauth.RequireBearerToken(verifier, &sdkauth.RequireBearerTokenOptions{AllowMissingExpiration: true})
	return a.Middleware(withTokenInfo(h))
}

type server struct {
	svc service.API
	log *slog.Logger
}

// authorize installs the principal from the request into ctx and performs
// the transport-level scope pre-check (the service re-checks).
func authorize(ctx context.Context, req *mcp.CallToolRequest, scope config.Scope) (context.Context, error) {
	if auth.PrincipalFrom(ctx) == nil && req != nil && req.Extra != nil && req.Extra.TokenInfo != nil {
		if p, ok := req.Extra.TokenInfo.Extra[principalKey].(*auth.Principal); ok {
			ctx = auth.WithPrincipal(ctx, p)
		}
	}
	if _, err := auth.Require(ctx, scope); err != nil {
		return ctx, toolError(err, scope)
	}
	return ctx, nil
}

// toolError converts service errors to messages suitable for a tool error
// result (IsError=true), never a transport failure.
func toolError(err error, scope config.Scope) error {
	switch {
	case errors.Is(err, auth.ErrUnauthenticated):
		return errors.New("authentication required: missing or invalid bearer token")
	case errors.Is(err, auth.ErrForbidden):
		if scope != "" {
			return fmt.Errorf("permission denied: this tool requires a token with the %q scope", scope)
		}
		return errors.New("permission denied: token lacks the required scope")
	case errors.Is(err, store.ErrNotFound):
		return errors.New("not found: no such resource")
	case errors.Is(err, service.ErrInvalid), errors.Is(err, service.ErrConflict):
		return err
	}
	return errors.New("internal error")
}

func (s *server) fail(ctx context.Context, tool string, err error, scope config.Scope) error {
	terr := toolError(err, scope)
	if terr.Error() == "internal error" {
		s.log.ErrorContext(ctx, "mcp tool failed", "tool", tool, "error", err)
	}
	return terr
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", service.ErrInvalid, fmt.Sprintf(format, args...))
}

func text(format string, args ...any) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, args...)}}}
}

func page(limit, offset int) (store.Page, error) {
	if limit == 0 {
		limit = defaultLimit
	}
	if limit < 1 || limit > maxLimit {
		return store.Page{}, invalid("limit must be between 1 and %d", maxLimit)
	}
	if offset < 0 {
		return store.Page{}, invalid("offset must be non-negative")
	}
	return store.Page{Limit: limit, Offset: offset}, nil
}

func ptr[T any](v T) *T { return &v }

func readOnly(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(false)}
}

func mutating(title string, destructive, idempotent bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, DestructiveHint: ptr(destructive), IdempotentHint: idempotent, OpenWorldHint: ptr(false)}
}

// --- tool inputs / outputs ---

type noInput struct{}

type namespaceInput struct {
	Namespace string `json:"namespace" jsonschema:"Kubernetes namespace to scan"`
}

type scanIDInput struct {
	ScanID string `json:"scan_id" jsonschema:"Scan run ID returned by scan_cluster/scan_namespace or list_scans"`
}

type idInput struct {
	ID string `json:"id" jsonschema:"ID of the object"`
}

type ackInput struct {
	ID     string `json:"id" jsonschema:"Finding ID"`
	Reason string `json:"reason,omitempty" jsonschema:"Why the finding is acknowledged (recorded for audit)"`
}

type listScansInput struct {
	Status    string `json:"status,omitempty" jsonschema:"Filter by status: pending, running, succeeded, partial, failed or cancelled"`
	Scope     string `json:"scope,omitempty" jsonschema:"Filter by scope: cluster or namespace"`
	Namespace string `json:"namespace,omitempty" jsonschema:"Filter namespace scans by namespace"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Page size, 1-500 (default 50)"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Number of items to skip"`
}

type listFindingsInput struct {
	Status        string `json:"status,omitempty" jsonschema:"open or resolved (default: all)"`
	Severity      string `json:"severity,omitempty" jsonschema:"CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN"`
	Namespace     string `json:"namespace,omitempty" jsonschema:"Only findings in images used by active workloads in this namespace"`
	Image         string `json:"image,omitempty" jsonschema:"Image key (repository@digest or image reference)"`
	Vulnerability string `json:"vulnerability,omitempty" jsonschema:"Vulnerability ID, e.g. CVE-2024-3094"`
	Acknowledged  *bool  `json:"acknowledged,omitempty" jsonschema:"Filter by acknowledgement state"`
	Deployed      *bool  `json:"deployed,omitempty" jsonschema:"true: only images still deployed; false: only images no longer deployed"`
	Limit         int    `json:"limit,omitempty" jsonschema:"Page size, 1-500 (default 50)"`
	Offset        int    `json:"offset,omitempty" jsonschema:"Number of items to skip"`
}

type createSilenceInput struct {
	Kind      string `json:"kind" jsonschema:"What to silence: finding, image, namespace or vulnerability"`
	Target    string `json:"target" jsonschema:"Finding ID, image key, namespace name or vulnerability ID (matching kind)"`
	Reason    string `json:"reason,omitempty" jsonschema:"Why the silence exists"`
	Duration  string `json:"duration,omitempty" jsonschema:"Lifetime as a Go duration, e.g. 720h; omit duration and expires_at for no expiry"`
	ExpiresAt string `json:"expires_at,omitempty" jsonschema:"Absolute expiry time (RFC 3339), alternative to duration"`
}

type listSilencesInput struct {
	IncludeInactive bool `json:"include_inactive,omitempty" jsonschema:"Also return expired and revoked silences"`
}

type scanOutput struct {
	Scan store.ScanRun `json:"scan"`
}

type scanStatusOutput struct {
	Scan service.ScanStatus `json:"scan"`
}

type scanListOutput struct {
	Items  []store.ScanRun `json:"items"`
	Total  int64           `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
}

type findingListOutput struct {
	Items  []store.Finding `json:"items"`
	Total  int64           `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
}

type findingDetailOutput struct {
	Finding service.FindingDetail `json:"finding"`
}

type findingOutput struct {
	Finding store.Finding `json:"finding"`
}

type silenceOutput struct {
	Silence store.Silence `json:"silence"`
}

type silenceListOutput struct {
	Items []store.Silence `json:"items"`
	Total int             `json:"total"`
}

type summaryOutput struct {
	Summary store.Summary `json:"summary"`
}

// --- registration ---

func (s *server) register(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "scan_cluster",
		Description: "Trigger a vulnerability scan of every container image running in the cluster. Returns immediately with the scan run; poll get_scan_status for progress. Requires the scan scope.",
		Annotations: mutating("Scan cluster", false, false),
	}, s.scanCluster)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "scan_namespace",
		Description: "Trigger a vulnerability scan of the container images running in one namespace. Returns immediately; poll get_scan_status. Requires the scan scope.",
		Annotations: mutating("Scan namespace", false, false),
	}, s.scanNamespace)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_scan_status",
		Description: "Get a scan run's status and progress, including its per-image jobs.",
		Annotations: readOnly("Get scan status"),
	}, s.getScanStatus)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_scans",
		Description: "List scan runs, newest first, with optional status/scope/namespace filters and pagination.",
		Annotations: readOnly("List scans"),
	}, s.listScans)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_findings",
		Description: "List vulnerability findings, newest first, filtered by status, severity, namespace, image, vulnerability ID, acknowledgement or deployment state. Paginated (limit up to 500).",
		Annotations: readOnly("List findings"),
	}, s.listFindings)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_finding",
		Description: "Get one finding with its image, the workloads and namespaces using that image, and whether a silence covers it.",
		Annotations: readOnly("Get finding"),
	}, s.getFinding)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "acknowledge_finding",
		Description: "Mark a finding as acknowledged (triaged) with an optional reason. Requires the manage scope.",
		Annotations: mutating("Acknowledge finding", false, true),
	}, s.acknowledge)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "unacknowledge_finding",
		Description: "Remove a finding's acknowledgement. Requires the manage scope.",
		Annotations: mutating("Unacknowledge finding", true, true),
	}, s.unacknowledge)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_silence",
		Description: "Create a silence that suppresses notifications (not visibility) for a finding, image, namespace or vulnerability ID, optionally time-bounded. Requires the manage scope.",
		Annotations: mutating("Create silence", false, false),
	}, s.createSilence)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_silences",
		Description: "List active silences, or all silences including expired and revoked ones.",
		Annotations: readOnly("List silences"),
	}, s.listSilences)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "remove_silence",
		Description: "Revoke a silence so matching findings notify again. Requires the manage scope.",
		Annotations: mutating("Remove silence", true, true),
	}, s.removeSilence)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "security_summary",
		Description: "Summarize the cluster's security state: open findings by severity and namespace, affected images, active silences and the latest scans.",
		Annotations: readOnly("Security summary"),
	}, s.summary)
}

// --- handlers ---

func (s *server) triggerScan(ctx context.Context, req *mcp.CallToolRequest, sr service.ScanRequest, tool string) (*mcp.CallToolResult, scanOutput, error) {
	ctx, err := authorize(ctx, req, config.ScopeScan)
	if err != nil {
		return nil, scanOutput{}, err
	}
	run, err := s.svc.TriggerScan(ctx, sr, store.TriggerMCP)
	if err != nil {
		return nil, scanOutput{}, s.fail(ctx, tool, err, config.ScopeScan)
	}
	where := "cluster"
	if run.Scope == store.ScopeNamespace {
		where = "namespace " + run.Namespace
	}
	return text("Scan %s of %s is %s. Use get_scan_status with scan_id %q to follow progress.", run.ID, where, run.Status, run.ID),
		scanOutput{Scan: *run}, nil
}

func (s *server) scanCluster(ctx context.Context, req *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, scanOutput, error) {
	return s.triggerScan(ctx, req, service.ScanRequest{Scope: store.ScopeCluster}, "scan_cluster")
}

func (s *server) scanNamespace(ctx context.Context, req *mcp.CallToolRequest, in namespaceInput) (*mcp.CallToolResult, scanOutput, error) {
	if strings.TrimSpace(in.Namespace) == "" {
		return nil, scanOutput{}, invalid("namespace is required")
	}
	return s.triggerScan(ctx, req, service.ScanRequest{Scope: store.ScopeNamespace, Namespace: in.Namespace}, "scan_namespace")
}

func (s *server) getScanStatus(ctx context.Context, req *mcp.CallToolRequest, in scanIDInput) (*mcp.CallToolResult, scanStatusOutput, error) {
	ctx, err := authorize(ctx, req, config.ScopeRead)
	if err != nil {
		return nil, scanStatusOutput{}, err
	}
	st, err := s.svc.GetScan(ctx, in.ScanID)
	if err != nil {
		return nil, scanStatusOutput{}, s.fail(ctx, "get_scan_status", err, config.ScopeRead)
	}
	return text("Scan %s (%s) is %s: %d/%d images done, %d failed, %d new findings, %d resolved.",
			st.ID, st.Scope, st.Status, st.CompletedImages, st.TotalImages, st.FailedImages, st.NewFindings, st.ResolvedCount),
		scanStatusOutput{Scan: *st}, nil
}

func (s *server) listScans(ctx context.Context, req *mcp.CallToolRequest, in listScansInput) (*mcp.CallToolResult, scanListOutput, error) {
	ctx, err := authorize(ctx, req, config.ScopeRead)
	if err != nil {
		return nil, scanListOutput{}, err
	}
	p, err := page(in.Limit, in.Offset)
	if err != nil {
		return nil, scanListOutput{}, err
	}
	items, total, err := s.svc.ListScans(ctx, store.ScanRunFilter{Status: in.Status, Scope: in.Scope, Namespace: in.Namespace, Page: p})
	if err != nil {
		return nil, scanListOutput{}, s.fail(ctx, "list_scans", err, config.ScopeRead)
	}
	if items == nil {
		items = []store.ScanRun{}
	}
	return text("Returned %d of %d scan runs (offset %d).", len(items), total, p.Offset),
		scanListOutput{Items: items, Total: total, Limit: p.Limit, Offset: p.Offset}, nil
}

func (s *server) listFindings(ctx context.Context, req *mcp.CallToolRequest, in listFindingsInput) (*mcp.CallToolResult, findingListOutput, error) {
	ctx, err := authorize(ctx, req, config.ScopeRead)
	if err != nil {
		return nil, findingListOutput{}, err
	}
	p, err := page(in.Limit, in.Offset)
	if err != nil {
		return nil, findingListOutput{}, err
	}
	f := store.FindingFilter{
		Status:          strings.ToLower(in.Status),
		Severity:        strings.ToUpper(in.Severity),
		Namespace:       in.Namespace,
		ImageKey:        in.Image,
		VulnerabilityID: in.Vulnerability,
		Acknowledged:    in.Acknowledged,
		Deployed:        in.Deployed,
		Page:            p,
	}
	if f.Status != "" && f.Status != store.FindingOpen && f.Status != store.FindingResolved {
		return nil, findingListOutput{}, invalid("status must be open or resolved")
	}
	items, total, err := s.svc.ListFindings(ctx, f)
	if err != nil {
		return nil, findingListOutput{}, s.fail(ctx, "list_findings", err, config.ScopeRead)
	}
	if items == nil {
		items = []store.Finding{}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Returned %d of %d findings (offset %d).", len(items), total, p.Offset)
	for i, it := range items {
		if i == 10 {
			fmt.Fprintf(&b, "\n... and %d more in structured output", len(items)-10)
			break
		}
		fmt.Fprintf(&b, "\n- %s %s in %s %s (%s)", it.Severity, it.VulnerabilityID, it.PkgName, it.InstalledVersion, it.ImageKey)
	}
	return text("%s", b.String()), findingListOutput{Items: items, Total: total, Limit: p.Limit, Offset: p.Offset}, nil
}

func (s *server) getFinding(ctx context.Context, req *mcp.CallToolRequest, in idInput) (*mcp.CallToolResult, findingDetailOutput, error) {
	ctx, err := authorize(ctx, req, config.ScopeRead)
	if err != nil {
		return nil, findingDetailOutput{}, err
	}
	d, err := s.svc.GetFinding(ctx, in.ID)
	if err != nil {
		return nil, findingDetailOutput{}, s.fail(ctx, "get_finding", err, config.ScopeRead)
	}
	if d.Workloads == nil {
		d.Workloads = []store.Workload{}
	}
	if d.Namespaces == nil {
		d.Namespaces = []string{}
	}
	fix := "no fix available"
	if d.FixedVersion != "" {
		fix = "fixed in " + d.FixedVersion
	}
	return text("%s %s in %s %s (%s), %s; status %s, %d workloads in namespaces [%s], silenced=%t.",
			d.Severity, d.VulnerabilityID, d.PkgName, d.InstalledVersion, d.ImageKey, fix, d.Status,
			len(d.Workloads), strings.Join(d.Namespaces, ", "), d.Silenced),
		findingDetailOutput{Finding: *d}, nil
}

func (s *server) acknowledge(ctx context.Context, req *mcp.CallToolRequest, in ackInput) (*mcp.CallToolResult, findingOutput, error) {
	ctx, err := authorize(ctx, req, config.ScopeManage)
	if err != nil {
		return nil, findingOutput{}, err
	}
	f, err := s.svc.Acknowledge(ctx, in.ID, service.AckRequest{Reason: in.Reason})
	if err != nil {
		return nil, findingOutput{}, s.fail(ctx, "acknowledge_finding", err, config.ScopeManage)
	}
	return text("Acknowledged finding %s (%s).", f.ID, f.VulnerabilityID), findingOutput{Finding: *f}, nil
}

func (s *server) unacknowledge(ctx context.Context, req *mcp.CallToolRequest, in idInput) (*mcp.CallToolResult, findingOutput, error) {
	ctx, err := authorize(ctx, req, config.ScopeManage)
	if err != nil {
		return nil, findingOutput{}, err
	}
	f, err := s.svc.Unacknowledge(ctx, in.ID)
	if err != nil {
		return nil, findingOutput{}, s.fail(ctx, "unacknowledge_finding", err, config.ScopeManage)
	}
	return text("Removed acknowledgement from finding %s (%s).", f.ID, f.VulnerabilityID), findingOutput{Finding: *f}, nil
}

func (s *server) createSilence(ctx context.Context, req *mcp.CallToolRequest, in createSilenceInput) (*mcp.CallToolResult, silenceOutput, error) {
	ctx, err := authorize(ctx, req, config.ScopeManage)
	if err != nil {
		return nil, silenceOutput{}, err
	}
	sr := service.SilenceRequest{Kind: in.Kind, Target: in.Target, Reason: in.Reason, Duration: in.Duration}
	if in.ExpiresAt != "" {
		t, perr := time.Parse(time.RFC3339, in.ExpiresAt)
		if perr != nil {
			return nil, silenceOutput{}, invalid("expires_at must be an RFC 3339 timestamp, e.g. 2026-12-31T00:00:00Z")
		}
		sr.ExpiresAt = &t
	}
	sil, err := s.svc.CreateSilence(ctx, sr)
	if err != nil {
		return nil, silenceOutput{}, s.fail(ctx, "create_silence", err, config.ScopeManage)
	}
	until := "no expiry"
	if sil.ExpiresAt != nil {
		until = "until " + sil.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return text("Created silence %s for %s %q (%s).", sil.ID, sil.Kind, sil.Target, until), silenceOutput{Silence: *sil}, nil
}

func (s *server) listSilences(ctx context.Context, req *mcp.CallToolRequest, in listSilencesInput) (*mcp.CallToolResult, silenceListOutput, error) {
	ctx, err := authorize(ctx, req, config.ScopeRead)
	if err != nil {
		return nil, silenceListOutput{}, err
	}
	items, err := s.svc.ListSilences(ctx, in.IncludeInactive)
	if err != nil {
		return nil, silenceListOutput{}, s.fail(ctx, "list_silences", err, config.ScopeRead)
	}
	if items == nil {
		items = []store.Silence{}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d silences.", len(items))
	for i, it := range items {
		if i == 20 {
			b.WriteString("\n...")
			break
		}
		fmt.Fprintf(&b, "\n- %s: %s %q", it.ID, it.Kind, it.Target)
	}
	return text("%s", b.String()), silenceListOutput{Items: items, Total: len(items)}, nil
}

func (s *server) removeSilence(ctx context.Context, req *mcp.CallToolRequest, in idInput) (*mcp.CallToolResult, silenceOutput, error) {
	ctx, err := authorize(ctx, req, config.ScopeManage)
	if err != nil {
		return nil, silenceOutput{}, err
	}
	sil, err := s.svc.RevokeSilence(ctx, in.ID)
	if err != nil {
		return nil, silenceOutput{}, s.fail(ctx, "remove_silence", err, config.ScopeManage)
	}
	return text("Revoked silence %s (%s %q).", sil.ID, sil.Kind, sil.Target), silenceOutput{Silence: *sil}, nil
}

func (s *server) summary(ctx context.Context, req *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, summaryOutput, error) {
	ctx, err := authorize(ctx, req, config.ScopeRead)
	if err != nil {
		return nil, summaryOutput{}, err
	}
	sum, err := s.svc.Summary(ctx)
	if err != nil {
		return nil, summaryOutput{}, s.fail(ctx, "security_summary", err, config.ScopeRead)
	}
	if sum.OpenBySeverity == nil {
		sum.OpenBySeverity = map[string]int64{}
	}
	if sum.OpenByNamespace == nil {
		sum.OpenByNamespace = map[string]int64{}
	}
	var sev []string
	for _, k := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		if n := sum.OpenBySeverity[k]; n > 0 {
			sev = append(sev, fmt.Sprintf("%s %d", k, n))
		}
	}
	last := "no scan yet"
	if sum.LastScan != nil {
		last = fmt.Sprintf("last scan %s %s at %s", sum.LastScan.ID, sum.LastScan.Status, sum.LastScan.CreatedAt.UTC().Format(time.RFC3339))
	}
	return text("%d open findings (%d unacknowledged) [%s] across %d affected of %d deployed images; %d active silences; %s.",
			sum.OpenFindings, sum.OpenUnacknowledged, strings.Join(sev, ", "), sum.AffectedImages, sum.DeployedImages, sum.ActiveSilences, last),
		summaryOutput{Summary: *sum}, nil
}

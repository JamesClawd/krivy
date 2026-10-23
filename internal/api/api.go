// Package api implements Krivy's REST API (/api/v1). Handlers are thin:
// they parse and validate HTTP input, call service.API (which enforces
// authorization), and render JSON. A per-route scope pre-check rejects
// under-privileged tokens before the service is reached (defense in depth).
package api

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/l4r-s/krivy/internal/auth"
	"github.com/l4r-s/krivy/internal/config"
	"github.com/l4r-s/krivy/internal/service"
	"github.com/l4r-s/krivy/internal/store"
)

// Prefix is the path prefix every route lives under.
const Prefix = "/api/v1"

// MaxBodyBytes bounds request bodies.
const MaxBodyBytes = 1 << 20

// Pagination bounds.
const (
	DefaultLimit = 50
	MaxLimit     = 500
)

//go:embed openapi.yaml
var openAPISpec []byte

// OpenAPISpec returns the embedded OpenAPI 3.1 document.
func OpenAPISpec() []byte { return openAPISpec }

type handler struct {
	svc    service.API
	log    *slog.Logger
	routes []route
}

// route is one registered endpoint. Scope "" means unauthenticated.
type route struct {
	Method  string
	Path    string
	Scope   config.Scope
	handler func(*handler, http.ResponseWriter, *http.Request)
}

func routeTable() []route {
	return []route{
		{http.MethodPost, Prefix + "/scans", config.ScopeScan, (*handler).triggerScan},
		{http.MethodGet, Prefix + "/scans", config.ScopeRead, (*handler).listScans},
		{http.MethodGet, Prefix + "/scans/{id}", config.ScopeRead, (*handler).getScan},
		{http.MethodPost, Prefix + "/scans/{id}/cancel", config.ScopeScan, (*handler).cancelScan},
		{http.MethodGet, Prefix + "/findings", config.ScopeRead, (*handler).listFindings},
		{http.MethodGet, Prefix + "/findings/{id}", config.ScopeRead, (*handler).getFinding},
		{http.MethodPost, Prefix + "/findings/{id}/acknowledge", config.ScopeManage, (*handler).acknowledge},
		{http.MethodDelete, Prefix + "/findings/{id}/acknowledge", config.ScopeManage, (*handler).unacknowledge},
		{http.MethodGet, Prefix + "/silences", config.ScopeRead, (*handler).listSilences},
		{http.MethodPost, Prefix + "/silences", config.ScopeManage, (*handler).createSilence},
		{http.MethodDelete, Prefix + "/silences/{id}", config.ScopeManage, (*handler).revokeSilence},
		{http.MethodGet, Prefix + "/summary", config.ScopeRead, (*handler).summary},
		{http.MethodGet, Prefix + "/openapi.yaml", "", (*handler).openapi},
	}
}

// New returns the REST handler. It expects full request paths
// (/api/v1/...), so mount it as mux.Handle("/api/v1/", h) without
// stripping the prefix. All routes except /api/v1/openapi.yaml require a
// bearer token.
func New(svc service.API, a *auth.Authenticator, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	h := &handler{svc: svc, log: logger, routes: routeTable()}
	mux := http.NewServeMux()
	for _, rt := range h.routes {
		fn := rt.handler
		var hh http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fn(h, w, r) })
		if rt.Scope != "" {
			hh = a.Middleware(requireScope(rt.Scope, hh))
		}
		mux.Handle(rt.Method+" "+rt.Path, hh)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); pattern != "" {
			mux.ServeHTTP(w, r)
			return
		}
		// Unmatched: answer with JSON 405 or 404 instead of text/plain.
		var allowed []string
		for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			probe := r.Clone(r.Context())
			probe.Method = m
			if _, p := mux.Handler(probe); p != "" {
				allowed = append(allowed, m)
			}
		}
		if len(allowed) > 0 {
			w.Header().Set("Allow", strings.Join(allowed, ", "))
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "no such endpoint")
	})
}

// requireScope is the transport-level pre-check; the service re-checks.
func requireScope(s config.Scope, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := auth.Require(r.Context(), s); err != nil {
			writeAuthError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- responses ---

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Page is a paginated list response.
type Page[T any] struct {
	Items  []T   `json:"items"`
	Total  int64 `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}

// List is a non-paginated list response.
type List[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{Error: errorDetail{Code: code, Message: msg}})
}

func writeAuthError(w http.ResponseWriter, err error) {
	if errors.Is(err, auth.ErrForbidden) {
		writeError(w, http.StatusForbidden, "forbidden", "token lacks the required scope")
		return
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="krivy"`)
	writeError(w, http.StatusUnauthorized, "unauthenticated", "missing or invalid bearer token")
}

// fail maps service/store errors to HTTP errors.
func (h *handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrUnauthenticated), errors.Is(err, auth.ErrForbidden):
		writeAuthError(w, err)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, service.ErrInvalid):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, service.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", err.Error())
	default:
		h.log.ErrorContext(r.Context(), "api request failed",
			"method", r.Method, "path", r.URL.Path, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

func badRequest(w http.ResponseWriter, format string, args ...any) {
	writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf(format, args...))
}

// decodeBody decodes a JSON object into v. An empty body is accepted when
// allowEmpty is set (v keeps its zero value). It writes the error response
// and returns false on failure.
func decodeBody(w http.ResponseWriter, r *http.Request, v any, allowEmpty bool) bool {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.Is(err, io.EOF) && allowEmpty:
			return true
		case errors.Is(err, io.EOF):
			badRequest(w, "request body is required")
		case errors.As(err, &mbe):
			badRequest(w, "request body exceeds %d bytes", MaxBodyBytes)
		default:
			badRequest(w, "invalid JSON body: %v", err)
		}
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		badRequest(w, "request body must contain a single JSON object")
		return false
	}
	return true
}

// --- query parsing ---

func parsePage(q url.Values) (store.Page, error) {
	p := store.Page{Limit: DefaultLimit}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxLimit {
			return p, fmt.Errorf("limit must be an integer between 1 and %d", MaxLimit)
		}
		p.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return p, errors.New("offset must be a non-negative integer")
		}
		p.Offset = n
	}
	return p, nil
}

func parseBool(q url.Values, name string) (*bool, error) {
	v := q.Get(name)
	if v == "" {
		return nil, nil
	}
	switch strings.ToLower(v) {
	case "true":
		b := true
		return &b, nil
	case "false":
		b := false
		return &b, nil
	}
	return nil, fmt.Errorf("%s must be true or false", name)
}

func oneOf(q url.Values, name string, allowed ...string) (string, error) {
	v := q.Get(name)
	if v == "" {
		return "", nil
	}
	for _, a := range allowed {
		if strings.EqualFold(v, a) {
			return a, nil
		}
	}
	return "", fmt.Errorf("%s must be one of %s", name, strings.Join(allowed, ", "))
}

var (
	scanStatuses    = []string{store.StatusPending, store.StatusRunning, store.StatusSucceeded, store.StatusPartial, store.StatusFailed, store.StatusCancelled}
	scanScopes      = []string{store.ScopeCluster, store.ScopeNamespace}
	findingStatuses = []string{store.FindingOpen, store.FindingResolved}
	severities      = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
)

// --- scans ---

func (h *handler) triggerScan(w http.ResponseWriter, r *http.Request) {
	var req service.ScanRequest
	if !decodeBody(w, r, &req, true) {
		return
	}
	if req.Scope == "" {
		req.Scope = store.ScopeCluster
		if req.Namespace != "" {
			req.Scope = store.ScopeNamespace
		}
	}
	run, err := h.svc.TriggerScan(r.Context(), req, store.TriggerAPI)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Location", Prefix+"/scans/"+url.PathEscape(run.ID))
	writeJSON(w, http.StatusAccepted, run)
}

func (h *handler) listScans(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, err := parsePage(q)
	if err != nil {
		badRequest(w, "%v", err)
		return
	}
	f := store.ScanRunFilter{Namespace: q.Get("namespace"), Page: page}
	if f.Status, err = oneOf(q, "status", scanStatuses...); err != nil {
		badRequest(w, "%v", err)
		return
	}
	if f.Scope, err = oneOf(q, "scope", scanScopes...); err != nil {
		badRequest(w, "%v", err)
		return
	}
	items, total, err := h.svc.ListScans(r.Context(), f)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newPage(items, total, page))
}

func (h *handler) getScan(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.GetScan(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (h *handler) cancelScan(w http.ResponseWriter, r *http.Request) {
	run, err := h.svc.CancelScan(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// --- findings ---

func (h *handler) listFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, err := parsePage(q)
	if err != nil {
		badRequest(w, "%v", err)
		return
	}
	f := store.FindingFilter{
		Namespace:       q.Get("namespace"),
		ImageKey:        q.Get("image"),
		VulnerabilityID: q.Get("vulnerability"),
		Page:            page,
	}
	if f.Status, err = oneOf(q, "status", findingStatuses...); err != nil {
		badRequest(w, "%v", err)
		return
	}
	if f.Severity, err = oneOf(q, "severity", severities...); err != nil {
		badRequest(w, "%v", err)
		return
	}
	if f.Acknowledged, err = parseBool(q, "acknowledged"); err != nil {
		badRequest(w, "%v", err)
		return
	}
	if f.Deployed, err = parseBool(q, "deployed"); err != nil {
		badRequest(w, "%v", err)
		return
	}
	items, total, err := h.svc.ListFindings(r.Context(), f)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newPage(items, total, page))
}

func (h *handler) getFinding(w http.ResponseWriter, r *http.Request) {
	d, err := h.svc.GetFinding(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (h *handler) acknowledge(w http.ResponseWriter, r *http.Request) {
	var req service.AckRequest
	if !decodeBody(w, r, &req, true) {
		return
	}
	f, err := h.svc.Acknowledge(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (h *handler) unacknowledge(w http.ResponseWriter, r *http.Request) {
	f, err := h.svc.Unacknowledge(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// --- silences ---

func (h *handler) listSilences(w http.ResponseWriter, r *http.Request) {
	all, err := parseBool(r.URL.Query(), "all")
	if err != nil {
		badRequest(w, "%v", err)
		return
	}
	items, err := h.svc.ListSilences(r.Context(), all != nil && *all)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if items == nil {
		items = []store.Silence{}
	}
	writeJSON(w, http.StatusOK, List[store.Silence]{Items: items, Total: len(items)})
}

func (h *handler) createSilence(w http.ResponseWriter, r *http.Request) {
	var req service.SilenceRequest
	if !decodeBody(w, r, &req, false) {
		return
	}
	s, err := h.svc.CreateSilence(r.Context(), req)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, s)
}

func (h *handler) revokeSilence(w http.ResponseWriter, r *http.Request) {
	s, err := h.svc.RevokeSilence(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

// --- misc ---

func (h *handler) summary(w http.ResponseWriter, r *http.Request) {
	s, err := h.svc.Summary(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *handler) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(openAPISpec)
}

func newPage[T any](items []T, total int64, p store.Page) Page[T] {
	if items == nil {
		items = []T{}
	}
	return Page[T]{Items: items, Total: total, Limit: p.Limit, Offset: p.Offset}
}

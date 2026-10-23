// Package httpserver assembles the controller's HTTP surface: health
// endpoints, the REST API and the MCP endpoint.
package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/l4r-s/krivy/internal/version"
)

// Pinger reports readiness of a dependency.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Handlers are the mounted sub-handlers; nil ones are skipped.
type Handlers struct {
	API http.Handler // serves /api/v1/...
	MCP http.Handler // serves /mcp
}

// New builds the root handler.
func New(h Handlers, ready Pinger, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if ready != nil {
			if err := ready.Ping(ctx); err != nil {
				log.Warn("readiness check failed", "error", err)
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("database unavailable\n"))
				return
			}
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"version": version.Version, "commit": version.Commit, "date": version.Date,
		})
	})
	if h.API != nil {
		mux.Handle("/api/", h.API)
	}
	if h.MCP != nil {
		mux.Handle("/mcp", h.MCP)
		mux.Handle("/mcp/", h.MCP)
	}
	return recoverer(log, securityHeaders(mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func recoverer(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				log.Error("panic in HTTP handler", "path", r.URL.Path, "panic", v)
				http.Error(w, `{"error":{"code":"internal","message":"internal error"}}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Package auth verifies static bearer tokens and their scopes. Tokens are
// held only as SHA-256 hashes in memory and compared in constant time.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/l4r-s/krivy/internal/config"
)

var (
	ErrUnauthenticated = errors.New("missing or invalid bearer token")
	ErrForbidden       = errors.New("token lacks required scope")
)

// Principal is an authenticated token identity.
type Principal struct {
	Name   string
	Scopes map[config.Scope]bool
}

// Has reports whether the principal holds scope. manage implies scan and
// read; scan implies read.
func (p *Principal) Has(s config.Scope) bool {
	if p == nil {
		return false
	}
	switch s {
	case config.ScopeRead:
		return p.Scopes[config.ScopeRead] || p.Scopes[config.ScopeScan] || p.Scopes[config.ScopeManage]
	case config.ScopeScan:
		return p.Scopes[config.ScopeScan] || p.Scopes[config.ScopeManage]
	case config.ScopeManage:
		return p.Scopes[config.ScopeManage]
	}
	return false
}

// Actor is the audit name recorded for actions ("token:<name>").
func (p *Principal) Actor() string {
	if p == nil {
		return ""
	}
	return "token:" + p.Name
}

type entry struct {
	hash      [32]byte
	principal *Principal
}

// Authenticator verifies bearer tokens.
type Authenticator struct {
	entries []entry
}

// New builds an Authenticator from config; revoked tokens are dropped.
func New(tokens []config.TokenConfig) (*Authenticator, error) {
	a := &Authenticator{}
	for _, t := range tokens {
		if t.Revoked {
			continue
		}
		var h [32]byte
		if t.Token != "" {
			h = sha256.Sum256([]byte(t.Token))
		} else {
			b, err := hex.DecodeString(t.SHA256)
			if err != nil || len(b) != 32 {
				return nil, errors.New("auth: invalid sha256 for token " + t.Name)
			}
			copy(h[:], b)
		}
		p := &Principal{Name: t.Name, Scopes: map[config.Scope]bool{}}
		for _, s := range t.Scopes {
			p.Scopes[s] = true
		}
		a.entries = append(a.entries, entry{hash: h, principal: p})
	}
	return a, nil
}

// Enabled reports whether any token is configured.
func (a *Authenticator) Enabled() bool { return a != nil && len(a.entries) > 0 }

// Verify checks a raw token. All entries are compared to keep timing
// independent of which (if any) token matched.
func (a *Authenticator) Verify(token string) (*Principal, error) {
	if a == nil || token == "" {
		return nil, ErrUnauthenticated
	}
	h := sha256.Sum256([]byte(token))
	var match *Principal
	for _, e := range a.entries {
		if subtle.ConstantTimeCompare(h[:], e.hash[:]) == 1 {
			match = e.principal
		}
	}
	if match == nil {
		return nil, ErrUnauthenticated
	}
	return match, nil
}

// FromRequest extracts and verifies "Authorization: Bearer <token>".
func (a *Authenticator) FromRequest(r *http.Request) (*Principal, error) {
	h := r.Header.Get("Authorization")
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, ErrUnauthenticated
	}
	return a.Verify(strings.TrimSpace(tok))
}

type ctxKey struct{}

// WithPrincipal stores p in ctx.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// PrincipalFrom returns the principal stored in ctx, or nil.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// Require returns ErrUnauthenticated / ErrForbidden unless ctx carries a
// principal with scope.
func Require(ctx context.Context, s config.Scope) (*Principal, error) {
	p := PrincipalFrom(ctx)
	if p == nil {
		return nil, ErrUnauthenticated
	}
	if !p.Has(s) {
		return nil, ErrForbidden
	}
	return p, nil
}

// Middleware authenticates requests and stores the principal in the context.
// Unauthenticated requests get 401 with a WWW-Authenticate header. Scope
// checks happen in the service layer via Require.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := a.FromRequest(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="krivy"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"missing or invalid bearer token"}}`))
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

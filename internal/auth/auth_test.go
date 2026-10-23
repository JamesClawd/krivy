package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/l4r-s/krivy/internal/config"
)

const (
	readTok    = "read-token-0123456789"
	scanTok    = "scan-token-0123456789"
	manageTok  = "manage-token-0123456789"
	revokedTok = "revoked-token-0123456789"
	hashedTok  = "hashed-token-0123456789"
)

func hexSHA(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func newAuth(t *testing.T) *Authenticator {
	t.Helper()
	a, err := New([]config.TokenConfig{
		{Name: "reader", Token: readTok, Scopes: []config.Scope{config.ScopeRead}},
		{Name: "scanner", Token: scanTok, Scopes: []config.Scope{config.ScopeScan}},
		{Name: "admin", Token: manageTok, Scopes: []config.Scope{config.ScopeManage}},
		{Name: "old", Token: revokedTok, Scopes: []config.Scope{config.ScopeManage}, Revoked: true},
		{Name: "hashed", SHA256: hexSHA(hashedTok), Scopes: []config.Scope{config.ScopeRead}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestVerify(t *testing.T) {
	a := newAuth(t)
	for _, tc := range []struct {
		name, token, want string
	}{
		{"read", readTok, "reader"},
		{"scan", scanTok, "scanner"},
		{"manage", manageTok, "admin"},
		{"sha256 form", hashedTok, "hashed"},
		{"revoked", revokedTok, ""},
		{"unknown", "nope-nope-nope-nope", ""},
		{"empty", "", ""},
		{"hash itself is not a token", hexSHA(hashedTok), ""},
		{"prefix", readTok[:10], ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := a.Verify(tc.token)
			if tc.want == "" {
				if !errors.Is(err, ErrUnauthenticated) || p != nil {
					t.Fatalf("Verify = %v, %v; want ErrUnauthenticated", p, err)
				}
				return
			}
			if err != nil || p.Name != tc.want {
				t.Fatalf("Verify = %v, %v; want %s", p, err, tc.want)
			}
			if p.Actor() != "token:"+tc.want {
				t.Fatalf("Actor = %q", p.Actor())
			}
		})
	}
}

func TestNewErrorsAndEnabled(t *testing.T) {
	if _, err := New([]config.TokenConfig{{Name: "x", SHA256: "zz"}}); err == nil {
		t.Fatal("expected invalid sha256 error")
	}
	if _, err := New([]config.TokenConfig{{Name: "x", SHA256: "abcd"}}); err == nil {
		t.Fatal("expected wrong-length sha256 error")
	}
	empty, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Enabled() {
		t.Fatal("empty authenticator should not be enabled")
	}
	onlyRevoked, _ := New([]config.TokenConfig{{Name: "r", Token: revokedTok, Revoked: true}})
	if onlyRevoked.Enabled() {
		t.Fatal("only revoked tokens should not enable auth")
	}
	var nilA *Authenticator
	if nilA.Enabled() {
		t.Fatal("nil authenticator enabled")
	}
	if _, err := nilA.Verify(readTok); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("nil Verify err = %v", err)
	}
	if !newAuth(t).Enabled() {
		t.Fatal("expected enabled")
	}
}

func TestScopeHierarchy(t *testing.T) {
	mk := func(s ...config.Scope) *Principal {
		p := &Principal{Name: "p", Scopes: map[config.Scope]bool{}}
		for _, x := range s {
			p.Scopes[x] = true
		}
		return p
	}
	for _, tc := range []struct {
		name                    string
		p                       *Principal
		read, scan, manage, odd bool
	}{
		{"read", mk(config.ScopeRead), true, false, false, false},
		{"scan", mk(config.ScopeScan), true, true, false, false},
		{"manage", mk(config.ScopeManage), true, true, true, false},
		{"read+scan", mk(config.ScopeRead, config.ScopeScan), true, true, false, false},
		{"none", mk(), false, false, false, false},
		{"nil", nil, false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.Has(config.ScopeRead); got != tc.read {
				t.Errorf("read = %v", got)
			}
			if got := tc.p.Has(config.ScopeScan); got != tc.scan {
				t.Errorf("scan = %v", got)
			}
			if got := tc.p.Has(config.ScopeManage); got != tc.manage {
				t.Errorf("manage = %v", got)
			}
			if got := tc.p.Has("weird"); got != tc.odd {
				t.Errorf("unknown scope = %v", got)
			}
		})
	}
	var nilP *Principal
	if nilP.Actor() != "" {
		t.Fatal("nil actor should be empty")
	}
}

func TestRequire(t *testing.T) {
	a := newAuth(t)
	reader, _ := a.Verify(readTok)
	scanner, _ := a.Verify(scanTok)
	admin, _ := a.Verify(manageTok)
	for _, tc := range []struct {
		name  string
		p     *Principal
		scope config.Scope
		want  error
	}{
		{"no principal", nil, config.ScopeRead, ErrUnauthenticated},
		{"read ok", reader, config.ScopeRead, nil},
		{"read cannot scan", reader, config.ScopeScan, ErrForbidden},
		{"read cannot manage", reader, config.ScopeManage, ErrForbidden},
		{"scan can read", scanner, config.ScopeRead, nil},
		{"scan ok", scanner, config.ScopeScan, nil},
		{"scan cannot manage", scanner, config.ScopeManage, ErrForbidden},
		{"manage all", admin, config.ScopeManage, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.p != nil {
				ctx = WithPrincipal(ctx, tc.p)
			}
			p, err := Require(ctx, tc.scope)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want == nil && p != tc.p {
				t.Fatalf("principal = %v", p)
			}
		})
	}
	if PrincipalFrom(context.Background()) != nil {
		t.Fatal("expected nil principal")
	}
}

func TestMiddlewareAndHeaderParsing(t *testing.T) {
	a := newAuth(t)
	var gotPrincipal *Principal
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPrincipal = PrincipalFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		name, header string
		wantCode     int
		wantName     string
	}{
		{"bearer", "Bearer " + readTok, 204, "reader"},
		{"lowercase scheme", "bearer " + manageTok, 204, "admin"},
		{"uppercase scheme", "BEARER " + scanTok, 204, "scanner"},
		{"extra spaces", "Bearer   " + readTok + "  ", 204, "reader"},
		{"missing", "", 401, ""},
		{"basic scheme", "Basic " + readTok, 401, ""},
		{"no token", "Bearer", 401, ""},
		{"empty token", "Bearer ", 401, ""},
		{"token only", readTok, 401, ""},
		{"invalid token", "Bearer invalid-invalid-invalid", 401, ""},
		{"revoked token", "Bearer " + revokedTok, 401, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotPrincipal = nil
			req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("code = %d, want %d", rec.Code, tc.wantCode)
			}
			if tc.wantCode == 401 {
				if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="krivy"` {
					t.Fatalf("WWW-Authenticate = %q", got)
				}
				if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
					t.Fatalf("Content-Type = %q", ct)
				}
				if gotPrincipal != nil {
					t.Fatal("handler must not run when unauthenticated")
				}
				return
			}
			if gotPrincipal == nil || gotPrincipal.Name != tc.wantName {
				t.Fatalf("principal = %+v, want %s", gotPrincipal, tc.wantName)
			}
		})
	}
}

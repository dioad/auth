package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestBrowserConfigValidate(t *testing.T) {
	t.Parallel()

	valid := BrowserConfig{
		Issuer:       "https://issuer.example",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://console.example/auth/callback",
		CookieSecure: true,
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}

	invalid := valid
	invalid.CookieSecure = false
	if err := invalid.Validate(); err == nil {
		t.Fatal("expected validation error for insecure cookie config")
	}
}

func TestBrowserConfigToOIDCConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := BrowserConfig{
		Issuer:       "https://issuer.example",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://console.example/auth/callback",
		CookieSecure: true,
	}

	mw := cfg.ToOIDCConfig()

	if mw.LoginPath != "/auth/login" {
		t.Fatalf("expected default login path, got %q", mw.LoginPath)
	}
	if len(mw.Scopes) != 3 || mw.Scopes[0] != "openid" || mw.Scopes[1] != "profile" || mw.Scopes[2] != "email" {
		t.Fatalf("expected default scopes, got %v", mw.Scopes)
	}
	if mw.TokenCookie.Name != "auth_token" {
		t.Fatalf("expected auth token cookie name, got %q", mw.TokenCookie.Name)
	}
	if mw.RefreshWindow != 5*time.Minute {
		t.Fatalf("expected refresh window 5m, got %s", mw.RefreshWindow)
	}
}

func TestCallbackRejectsMissingCodeAndState(t *testing.T) {
	t.Parallel()

	h := &Handler{
		Config: OIDCConfig{StateCookie: CookieConfig{Name: "oidc_state"}},
		logger: zerolog.Nop(),
	}

	t.Run("missing code", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=abc", nil)
		req.AddCookie(&http.Cookie{Name: "oidc_state", Value: "abc"})
		w := httptest.NewRecorder()

		h.Callback().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("missing state", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=xyz", nil)
		w := httptest.NewRecorder()

		h.Callback().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

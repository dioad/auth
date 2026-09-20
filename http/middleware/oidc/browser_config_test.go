package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	require.NoError(t, valid.Validate())

	invalid := valid
	invalid.CookieSecure = false
	require.Error(t, invalid.Validate(), "expected validation error for insecure cookie config")
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

	require.Equal(t, "/auth/login", mw.LoginPath)
	require.Equal(t, []string{"openid", "profile", "email"}, mw.Scopes)
	require.Equal(t, "auth_token", mw.TokenCookie.Name)
	require.Equal(t, 5*time.Minute, mw.RefreshWindow)
}

func TestCallbackRejectsMissingCodeAndState(t *testing.T) {
	t.Parallel()

	h := &Handler{
		Config: OIDCConfig{StateCookie: CookieConfig{Name: "oidc_state"}},
	}

	t.Run("missing code", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=abc", nil)
		req.AddCookie(&http.Cookie{Name: "oidc_state", Value: "abc"})
		w := httptest.NewRecorder()

		h.Callback().ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing state", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=xyz", nil)
		w := httptest.NewRecorder()

		h.Callback().ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHandler_AppliesDefaults(t *testing.T) {
	h := NewHandler(nil, OIDCConfig{RedirectURI: "https://tunnel.example/callback"})

	require.Equal(t, "/login", h.Config.LoginPath)
	require.Equal(t, "/logout", h.Config.LogoutPath)
	require.Equal(t, "/callback", h.CallbackPath())

	for _, cc := range []struct {
		name string
		got  CookieConfig
	}{
		{"token", h.Config.TokenCookie},
		{"state", h.Config.StateCookie},
		{"refresh", h.Config.RefreshCookie},
		{"expiry", h.Config.TokenExpiryCookie},
	} {
		assert.NotEmptyf(t, cc.got.Name, "%s cookie name should default", cc.name)
		assert.Equalf(t, DefaultCookiePath, cc.got.Path, "%s cookie path should default", cc.name)
		assert.NotZerof(t, cc.got.MaxAge, "%s cookie max-age should default", cc.name)
		assert.Emptyf(t, cc.got.Domain, "%s cookie domain must stay empty by default", cc.name)
		assert.Truef(t, cc.got.Secure, "%s cookie must default Secure to true", cc.name)
	}
}

// TestNewHandler_AllowInsecureCookies_OptsOutOfSecureDefault is the
// regression test for the insecure-by-default session cookie: session
// cookies carry live OAuth access and refresh tokens, so Secure must default
// true, with plain-HTTP local development requiring an explicit opt-out —
// the same shape as oidc.ValidatorConfig.AllowInsecureHMAC.
func TestNewHandler_AllowInsecureCookies_OptsOutOfSecureDefault(t *testing.T) {
	h := NewHandler(nil, OIDCConfig{
		RedirectURI:          "https://tunnel.example/callback",
		AllowInsecureCookies: true,
	})

	assert.False(t, h.Config.TokenCookie.Secure)
	assert.False(t, h.Config.StateCookie.Secure)
	assert.False(t, h.Config.RefreshCookie.Secure)
	assert.False(t, h.Config.TokenExpiryCookie.Secure)
}

func TestNewHandler_PreservesExplicitConfig(t *testing.T) {
	h := NewHandler(nil, OIDCConfig{
		RedirectURI: "https://tunnel.example/callback",
		LoginPath:   "/start",
		LogoutPath:  "/end",
		TokenCookie: CookieConfig{Name: "custom_token"},
	})

	require.Equal(t, "/start", h.Config.LoginPath)
	require.Equal(t, "/end", h.Config.LogoutPath)
	require.Equal(t, "custom_token", h.Config.TokenCookie.Name)
}

func newTestHandler() *Handler {
	return NewHandler(nil, OIDCConfig{RedirectURI: "https://tunnel.example/callback"})
}

func TestHandler_Wrap_RedirectsUnauthenticatedRequestToLoginPath(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()

	called := false
	h.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(rr, req)

	require.False(t, called, "next handler must not run for an unauthenticated request")
	require.Equal(t, http.StatusSeeOther, rr.Code)
	require.Equal(t, "/login", rr.Header().Get("Location"))
}

// TestHandler_Wrap_ExemptsOwnRoutesFromTheGate is the regression test for the
// redirect loop: without this exemption, an unauthenticated request to
// LoginPath, CallbackPath, or LogoutPath would be redirected back to
// LoginPath by Wrap itself, before ever reaching the AuthStart/Callback/
// Logout handlers registered on the mux — login could never complete.
func TestHandler_Wrap_ExemptsOwnRoutesFromTheGate(t *testing.T) {
	h := newTestHandler()

	for _, path := range []string{h.LoginPath(), h.CallbackPath(), h.LogoutPath()} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()

			called := false
			h.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rr, req)

			require.True(t, called, "request to %s must reach next, not be redirected", path)
			require.Equal(t, http.StatusOK, rr.Code)
		})
	}
}

// TestHandler_Wrap_ForgedAuthorizationHeaderDoesNotBypassSessionCheck is the
// regression test for the sole-gate bypass: previously any request bearing a
// non-empty Authorization header — regardless of its value — skipped the
// cookie/session check entirely and reached next unauthenticated. When this
// Handler is a server's sole auth gate (its default, primary configuration)
// that let an attacker bypass authentication with a single forged header.
func TestHandler_Wrap_ForgedAuthorizationHeaderDoesNotBypassSessionCheck(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "forged-value")
	rr := httptest.NewRecorder()

	called := false
	h.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(rr, req)

	require.False(t, called, "next handler must not run for a forged Authorization header with no valid session")
	require.Equal(t, http.StatusSeeOther, rr.Code)
	require.Equal(t, "/login", rr.Header().Get("Location"))
}

// TestHandler_WithBearerPassthrough_ForwardsAuthorizationHeader verifies the
// opt-in escape hatch for callers that explicitly chain this Handler ahead of
// a separate bearer-token validator: passthrough only happens when requested.
func TestHandler_WithBearerPassthrough_ForwardsAuthorizationHeader(t *testing.T) {
	h := newTestHandler().WithBearerPassthrough(true)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rr := httptest.NewRecorder()

	called := false
	h.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	require.True(t, called, "next handler must run when bearer passthrough is explicitly enabled")
	require.Equal(t, http.StatusOK, rr.Code)
}

func TestHandler_Logout_ClearsCookiesAndRedirects(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, h.LogoutPath(), nil)
	rr := httptest.NewRecorder()

	h.Logout().ServeHTTP(rr, req)

	require.Equal(t, http.StatusFound, rr.Code)
	require.Equal(t, "/", rr.Header().Get("Location"))

	cleared := map[string]bool{}
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge < 0 || c.MaxAge == 0 {
			cleared[c.Name] = true
		}
	}
	assert.True(t, cleared[h.Config.TokenCookie.Name])
	assert.True(t, cleared[h.Config.RefreshCookie.Name])
	assert.True(t, cleared[h.Config.TokenExpiryCookie.Name])
}

func TestHandler_Callback_RejectsMissingCode(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, h.CallbackPath()+"?state=abc", nil)
	rr := httptest.NewRecorder()

	h.Callback().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandler_Callback_RejectsMissingState(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, h.CallbackPath()+"?code=abc", nil)
	rr := httptest.NewRecorder()

	h.Callback().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandler_Callback_RejectsMissingStateCookie(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, h.CallbackPath()+"?code=abc&state=xyz", nil)
	rr := httptest.NewRecorder()

	h.Callback().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandler_Callback_RejectsStateMismatch(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, h.CallbackPath()+"?code=abc&state=xyz", nil)
	req.AddCookie(h.Config.StateCookie.Cookie("different-state"))
	rr := httptest.NewRecorder()

	h.Callback().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/dioad/auth/authctx"
	"github.com/dioad/auth/oidc"
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
		{"id_token", h.Config.IDTokenCookie},
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
	assert.False(t, h.Config.IDTokenCookie.Secure)
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
	assert.True(t, cleared[h.Config.IDTokenCookie.Name])
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

func TestHandler_SaveTokenToCookies_SetsIDTokenCookieWhenPresent(t *testing.T) {
	h := newTestHandler()
	token := (&oauth2.Token{
		AccessToken:  "access",
		RefreshToken: "refresh",
		Expiry:       time.Now().Add(time.Hour),
	}).WithExtra(map[string]any{"id_token": "signed-id-token"})
	rr := httptest.NewRecorder()

	h.saveTokenToCookies(rr, token)

	var found bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == h.Config.IDTokenCookie.Name {
			found = true
			require.Equal(t, "signed-id-token", c.Value)
		}
	}
	require.True(t, found, "id token cookie should be set when the token carries an id_token")
}

// TestHandler_SaveTokenToCookies_OmitsIDTokenCookieWhenAbsent is the
// regression test for the refresh-drops-principal case: a refresh_token
// grant is not guaranteed to re-issue an id_token, so saving a refreshed
// token that carries none must not emit a Set-Cookie for the id token
// cookie at all — overwriting it with an empty value would clear the
// browser's existing (still valid) id token cookie on every refresh.
func TestHandler_SaveTokenToCookies_OmitsIDTokenCookieWhenAbsent(t *testing.T) {
	h := newTestHandler()
	token := &oauth2.Token{
		AccessToken:  "access",
		RefreshToken: "refresh",
		Expiry:       time.Now().Add(time.Hour),
	}
	rr := httptest.NewRecorder()

	h.saveTokenToCookies(rr, token)

	for _, c := range rr.Result().Cookies() {
		require.NotEqualf(t, h.Config.IDTokenCookie.Name, c.Name,
			"a token with no id_token must not overwrite the existing id token cookie")
	}
}

// newTestOIDCClientWithKey builds an *oidc.Client whose ValidateToken
// verifies RS256 tokens signed by key, issued by issuer.example, for
// clientID.
func newTestOIDCClientWithKey(t *testing.T, key *rsa.PrivateKey, clientID string) *oidc.Client {
	t.Helper()
	endpoint, err := oidc.NewEndpoint("https://issuer.example")
	require.NoError(t, err)
	return oidc.NewClient(
		endpoint,
		oidc.WithClientIDAndSecret(clientID, "test-client-secret"),
		oidc.WithKeyFunc(func(_ context.Context) (any, error) {
			return &key.PublicKey, nil
		}),
		oidc.WithValidatingSignatureAlgorithm(jwtvalidator.RS256),
	)
}

func signTestIDToken(t *testing.T, key *rsa.PrivateKey, clientID, subject string, expiry time.Time) string {
	t.Helper()
	claims := jwtv5.MapClaims{
		"iss": "https://issuer.example",
		"sub": subject,
		"aud": clientID,
		"exp": expiry.Unix(),
	}
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, claims)
	token.Header["kid"] = "test-rsa-key"
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

// newAuthenticatedRequest builds a request carrying a valid, non-expiring
// access/refresh/expiry session, so it passes Wrap's session check and
// reaches populatePrincipal. idToken is omitted from the request when "".
func newAuthenticatedRequest(h *Handler, idToken string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(h.Config.TokenCookie.Cookie("test-access-token"))
	req.AddCookie(h.Config.RefreshCookie.Cookie("test-refresh-token"))
	req.AddCookie(h.Config.TokenExpiryCookie.Cookie(time.Now().Add(time.Hour).Format(time.RFC3339)))
	if idToken != "" {
		req.AddCookie(h.Config.IDTokenCookie.Cookie(idToken))
	}
	return req
}

func TestHandler_Wrap_PopulatesPrincipalFromValidIDToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	client := newTestOIDCClientWithKey(t, key, "test-client-id")
	h := NewHandler(client, OIDCConfig{RedirectURI: "https://tunnel.example/callback"})

	idToken := signTestIDToken(t, key, "test-client-id", "test-subject", time.Now().Add(time.Hour))
	req := newAuthenticatedRequest(h, idToken)
	rr := httptest.NewRecorder()

	var gotPrincipal string
	var gotOK bool
	h.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPrincipal, gotOK = authctx.AuthenticatedPrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.True(t, gotOK, "principal should be populated from a valid id token cookie")
	require.Equal(t, "test-subject", gotPrincipal)
}

// TestHandler_Wrap_LeavesPrincipalAbsentWhenIDTokenCookieMissing is the
// explicit test for this design's fail-open-on-principal-only behavior: the
// id token is enrichment, not the session's auth gate, so its absence must
// not block a request whose access/refresh session is otherwise valid.
func TestHandler_Wrap_LeavesPrincipalAbsentWhenIDTokenCookieMissing(t *testing.T) {
	h := newTestHandler()
	req := newAuthenticatedRequest(h, "")
	rr := httptest.NewRecorder()

	called := false
	var gotOK bool
	h.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, gotOK = authctx.AuthenticatedPrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	require.True(t, called, "a missing id token must not block the request")
	require.Equal(t, http.StatusOK, rr.Code)
	require.False(t, gotOK)
}

// TestHandler_Wrap_LeavesPrincipalAbsentWhenIDTokenInvalid covers the same
// fail-open behavior when an id token cookie is present but fails signature
// verification (signed by a key other than the one the client trusts).
func TestHandler_Wrap_LeavesPrincipalAbsentWhenIDTokenInvalid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	client := newTestOIDCClientWithKey(t, key, "test-client-id")
	h := NewHandler(client, OIDCConfig{RedirectURI: "https://tunnel.example/callback"})

	idToken := signTestIDToken(t, otherKey, "test-client-id", "test-subject", time.Now().Add(time.Hour))
	req := newAuthenticatedRequest(h, idToken)
	rr := httptest.NewRecorder()

	called := false
	var gotOK bool
	h.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, gotOK = authctx.AuthenticatedPrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	require.True(t, called, "an invalid id token must not block the request")
	require.Equal(t, http.StatusOK, rr.Code)
	require.False(t, gotOK)
}

package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	authhttp "github.com/dioad/auth/http"
	"github.com/dioad/auth/http/hmac"
	oidcmw "github.com/dioad/auth/http/middleware/oidc"
	"github.com/dioad/auth/oidc"
	nethttp "github.com/dioad/net/http"
)

// startTestServer starts a real nethttp.Server on a loopback port, since
// nethttp.Server doesn't expose its handler for in-process testing (no
// exported ServeHTTP/Handler method). The server is shut down via t.Cleanup.
func startTestServer(t *testing.T, opts ...nethttp.ServerOption) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := nethttp.NewServer(nethttp.Config{}, opts...)

	go func() {
		_ = s.Serve(ln)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})

	return "http://" + ln.Addr().String()
}

// TestWithServerAuth_OIDC_RegistersRoutesWithoutRedirectLoop is the
// regression test for the bug where net.Server's middleware wraps the whole
// mux, so the OIDC gate would redirect a request for its own callback path
// straight back to LoginPath, forever. It uses an unreachable loopback issuer
// (127.0.0.1:1, connection-refused, no DNS lookup) so it stays fast and
// network-independent; the callback path's missing-code/state validation
// happens before any provider call, so it's a clean, deterministic 400.
func TestWithServerAuth_OIDC_RegistersRoutesWithoutRedirectLoop(t *testing.T) {
	cfg := authhttp.ServerConfig{
		Type: "oidc",
		OIDCAuthConfig: authhttp.OIDCServerConfig{
			ClientConfig: oidc.ClientConfig{
				EndpointConfig: oidc.EndpointConfig{URL: "http://127.0.0.1:1"},
				ClientID:       "client-id",
			},
			OIDCConfig: oidcmw.OIDCConfig{RedirectURI: "https://tunnel.example/callback"},
		},
	}

	base := startTestServer(t, WithServerAuth(cfg))

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(base + "/callback")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.NotEqualf(t, http.StatusSeeOther, resp.StatusCode,
		"unauthenticated request to the callback path must not be redirected back to the login gate")
	require.NotEqual(t, "/login", resp.Header.Get("Location"))
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "Callback should run and reject the missing code/state, not be gated")
}

// TestWithOAuth2Validator_RejectsRequestWithNoCredential is the regression
// test for the fail-open sibling of the bug fixed for the "type: jwt"
// dispatch path: OAuth2ValidatorHandler built a jwt.Handler without opting
// into WithRequireToken(true), so a request presenting no bearer token at
// all was forwarded to next unauthenticated instead of rejected.
func TestWithOAuth2Validator_RejectsRequestWithNoCredential(t *testing.T) {
	cfg := []oidc.ValidatorConfig{{
		URL:       "http://127.0.0.1:1",
		Issuer:    "http://127.0.0.1:1",
		Audiences: []string{"test-audience"},
	}}

	base := startTestServer(t, WithOAuth2Validator(cfg))

	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(base + "/secure")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"a request with no credential must be rejected, not forwarded unauthenticated")
}

func TestWithServerAuth_NonOIDC_RegistersNoLoginRoutes(t *testing.T) {
	cfg := authhttp.ServerConfig{
		Type: "hmac",
		HMACAuthConfig: hmac.ServerConfig{
			CommonConfig: hmac.CommonConfig{SharedKey: "test-shared-key"},
		},
	}

	base := startTestServer(t, WithServerAuth(cfg))

	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(base + "/login")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// hmac has no login flow to exempt: /login is just an ordinary path,
	// uniformly gated like everything else, so an unsigned request is
	// rejected by the hmac gate itself (401) rather than routed anywhere.
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "no login route should be registered for a non-oidc auth type")
}

const testHMACSecret = "test-secret"

func hmacValidatorConfig() []oidc.ValidatorConfig {
	return []oidc.ValidatorConfig{{
		HMACSecret:        testHMACSecret,
		AllowInsecureHMAC: true,
		Audiences:         []string{"test-audience"},
	}}
}

func signHMACToken(t *testing.T) string {
	t.Helper()

	now := time.Now()
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"sub": "test-user",
		"iss": "test-issuer",
		"aud": "test-audience",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	signed, err := token.SignedString([]byte(testHMACSecret))
	require.NoError(t, err)
	return signed
}

// TestOAuth2ValidatorHandler_TokenSource covers where the middleware accepts
// a bearer token from. A valid token in a cookie must be refused unless the
// caller opted in to that cookie by name: an API that browsers can reach must
// not accept a credential the browser attaches by itself.
func TestOAuth2ValidatorHandler_TokenSource(t *testing.T) {
	tests := []struct {
		name       string
		opts       []ValidatorHandlerOption
		header     bool
		cookieName string
		wantStatus int
	}{
		{name: "header is accepted by default", header: true, wantStatus: http.StatusOK},
		{name: "auth_token cookie is refused by default", cookieName: "auth_token", wantStatus: http.StatusUnauthorized},
		{
			name:       "opted-in cookie is accepted",
			opts:       []ValidatorHandlerOption{WithCookieTokenName("session")},
			cookieName: "session",
			wantStatus: http.StatusOK,
		},
		{
			name:       "cookie other than the opted-in one is refused",
			opts:       []ValidatorHandlerOption{WithCookieTokenName("session")},
			cookieName: "auth_token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "header is still accepted with a cookie opted in",
			opts:       []ValidatorHandlerOption{WithCookieTokenName("session"), WithValidatorDebug()},
			header:     true,
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw, err := OAuth2ValidatorHandler(hmacValidatorConfig(), tt.opts...)
			require.NoError(t, err)

			token := signHMACToken(t)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/secure", nil)
			if tt.header {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			if tt.cookieName != "" {
				req.AddCookie(&http.Cookie{Name: tt.cookieName, Value: token})
			}
			rr := httptest.NewRecorder()

			mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rr, req)

			require.Equal(t, tt.wantStatus, rr.Code)
		})
	}
}

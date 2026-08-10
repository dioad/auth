package server

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

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
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
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
// into WithRequireToken(true), so a request presenting no bearer token or
// cookie at all was forwarded to next unauthenticated instead of rejected —
// exactly the vulnerable configuration examples/oidc-auth/main.go documents.
func TestWithOAuth2Validator_RejectsRequestWithNoCredential(t *testing.T) {
	cfg := []oidc.ValidatorConfig{{
		EndpointConfig: oidc.EndpointConfig{URL: "http://127.0.0.1:1"},
		Issuer:         "http://127.0.0.1:1",
		Audiences:      []string{"test-audience"},
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

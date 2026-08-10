package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	oidcmw "github.com/dioad/auth/http/middleware/oidc"
	"github.com/dioad/auth/jwt"
	"github.com/dioad/auth/oidc"
)

func TestResolveAuthHandlerByType_JWT_RejectsRequestWithNoCredential(t *testing.T) {
	cfg := &ServerConfig{
		Type: "jwt",
		JWTAuthConfig: jwt.ValidatorConfig{
			Issuer:    "https://issuer.example",
			Audiences: []string{"my-tunnel"},
		},
	}

	h, err := NewHandler(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	called := false
	h.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(rr, req)

	require.False(t, called, "next handler must not run for a jwt-gated request with no credential")
	require.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestResolveAuthHandlerByType_OIDC_FailsFastOnMissingRedirectURI(t *testing.T) {
	cfg := &ServerConfig{
		Type: "oidc",
		OIDCAuthConfig: OIDCServerConfig{
			ClientConfig: oidc.ClientConfig{
				EndpointConfig: oidc.EndpointConfig{URL: "https://issuer.example"},
				ClientID:       "client-id",
			},
		},
	}

	_, err := NewHandler(cfg)
	require.Error(t, err)
}

func TestResolveAuthHandlerByType_OIDC_RegistersLoginRoutesAndRedirects(t *testing.T) {
	cfg := &ServerConfig{
		Type: "oidc",
		OIDCAuthConfig: OIDCServerConfig{
			ClientConfig: oidc.ClientConfig{
				EndpointConfig: oidc.EndpointConfig{URL: "https://issuer.example"},
				ClientID:       "client-id",
			},
			OIDCConfig: oidcmw.OIDCConfig{RedirectURI: "https://tunnel.example/callback"},
		},
	}

	h, err := NewHandler(cfg)
	require.NoError(t, err)

	lr, ok := h.LoginRoutes()
	require.True(t, ok, "oidc handler must implement LoginRoutable")
	require.Equal(t, "/login", lr.LoginPath())
	require.Equal(t, "/callback", lr.CallbackPath())

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()

	h.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler must not run for an unauthenticated request")
	})).ServeHTTP(rr, req)

	require.Equal(t, http.StatusSeeOther, rr.Code)
	require.Equal(t, "/login", rr.Header().Get("Location"))
}

package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth"
	"github.com/dioad/auth/authctx"
	"github.com/dioad/auth/http/server"
	"github.com/dioad/auth/oidc"
	"github.com/dioad/net/authz"
	nethttp "github.com/dioad/net/http"
)

func serve(t *testing.T, chain []nethttp.Middleware, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	nethttp.Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), chain...).ServeHTTP(rec, r)
	return rec
}

func TestAPIMiddlewares_WithoutValidatorsOnlyExtractsThePrincipal(t *testing.T) {
	t.Parallel()

	chain, err := server.APIMiddlewares(nil, auth.NewAllowAllPrincipalExtractor())
	require.NoError(t, err)

	assert.Len(t, chain, 1)
	rec := serve(t, chain, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestAPIMiddlewares_ValidatorsRejectARequestWithoutAToken(t *testing.T) {
	t.Parallel()

	validators := []oidc.ValidatorConfig{{Issuer: "https://issuer.example", HMACSecret: "0123456789abcdef0123456789abcdef", AllowInsecureHMAC: true}}
	chain, err := server.APIMiddlewares(validators, auth.NewAllowAllPrincipalExtractor())
	require.NoError(t, err)

	assert.Len(t, chain, 2, "validation runs before principal extraction")
	rec := serve(t, chain, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAPIMiddlewares_ReportsAnInvalidValidator(t *testing.T) {
	t.Parallel()

	_, err := server.APIMiddlewares([]oidc.ValidatorConfig{{}}, auth.NewAllowAllPrincipalExtractor())

	assert.ErrorContains(t, err, "building JWT middleware")
}

func TestAPIMiddlewares_WithoutAnExtractorLeavesExtractionOut(t *testing.T) {
	t.Parallel()

	chain, err := server.APIMiddlewares(nil, nil)
	require.NoError(t, err)

	assert.Empty(t, chain)
}

func TestAPIMiddlewares_PrincipalACLAdmitsOnlyWhatItAllows(t *testing.T) {
	t.Parallel()

	acl := authz.PrincipalACLConfig{AllowList: []string{"owner@example.com"}, DenyList: []string{"banned@example.com"}}
	chain, err := server.APIMiddlewares(nil, nil, server.WithPrincipalACL(acl))
	require.NoError(t, err)
	require.Len(t, chain, 1)

	tests := []struct {
		principal string
		want      int
	}{
		{"owner@example.com", http.StatusNoContent},
		{"stranger@example.com", http.StatusForbidden},
		{"banned@example.com", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.principal, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(authctx.ContextWithAuthenticatedPrincipal(t.Context(), tc.principal), http.MethodGet, "/", nil)

			assert.Equal(t, tc.want, serve(t, chain, req).Code)
		})
	}
}

func TestAPIMiddlewares_PrincipalACLRunsAfterValidationAndExtraction(t *testing.T) {
	t.Parallel()

	validators := []oidc.ValidatorConfig{{Issuer: "https://issuer.example", HMACSecret: "0123456789abcdef0123456789abcdef", AllowInsecureHMAC: true}}
	chain, err := server.APIMiddlewares(validators, auth.NewAllowAllPrincipalExtractor(),
		server.WithCookieTokenName("session"), server.WithPrincipalACL(authz.PrincipalACLConfig{}))
	require.NoError(t, err)

	assert.Len(t, chain, 3)
	rec := serve(t, chain, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "a request with no token never reaches the ACL")
}

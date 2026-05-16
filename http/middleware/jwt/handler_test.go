package jwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	authcontext "github.com/dioad/auth/http/context"
)

type stubTokenValidator struct {
	claims any
	err    error
}

func (s *stubTokenValidator) ValidateToken(_ context.Context, _ string) (any, error) {
	return s.claims, s.err
}

func (s *stubTokenValidator) String() string { return "stubTokenValidator" }

type sourceCustomClaims struct {
	Source string `json:"source"`
}

func (s *sourceCustomClaims) Validate(_ context.Context) error { return nil }

func makeSignedToken(t *testing.T, claims gojwt.MapClaims) string {
	t.Helper()
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)
	return signed
}

func TestHandler_PopulatesAuthenticatedCustomClaimsFromTokenPayload(t *testing.T) {
	now := time.Now()
	token := makeSignedToken(t, gojwt.MapClaims{
		"sub": "alice",
		"aud": "account",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"realm_access": map[string]any{
			"roles": []string{"connect-admin"},
		},
	})

	h := NewHandler(&stubTokenValidator{
		claims: &jwtvalidator.ValidatedClaims{
			RegisteredClaims: jwtvalidator.RegisteredClaims{Subject: "alice"},
		},
	}, "auth_token", zerolog.Nop())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := authcontext.AuthenticatedCustomClaimsFromContext(r.Context())
		require.True(t, ok)
		require.Equal(t, "alice", claims["sub"])

		realmAccess, ok := claims["realm_access"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, []any{"connect-admin"}, realmAccess["roles"])
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
}

func TestHandler_PrefersValidatedCustomClaimsOverTokenPayloadFallback(t *testing.T) {
	token := makeSignedToken(t, gojwt.MapClaims{"source": "token"})

	h := NewHandler(&stubTokenValidator{
		claims: &jwtvalidator.ValidatedClaims{
			RegisteredClaims: jwtvalidator.RegisteredClaims{Subject: "alice"},
			CustomClaims:     &sourceCustomClaims{Source: "validated"},
		},
	}, "auth_token", zerolog.Nop())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	h.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := authcontext.AuthenticatedCustomClaimsFromContext(r.Context())
		require.True(t, ok)
		require.Equal(t, "validated", claims["source"])
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
}

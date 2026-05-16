package jwt

import (
	"context"
	"testing"
	"time"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

type brokenCustomClaims struct {
	Bad chan int `json:"bad"`
}

func (b *brokenCustomClaims) Validate(_ context.Context) error { return nil }

type sourceCustomClaims struct {
	Source string `json:"source"`
}

func (s *sourceCustomClaims) Validate(_ context.Context) error { return nil }

func makeTokenString(t *testing.T, claims gojwt.MapClaims) string {
	t.Helper()
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)
	return signed
}

func TestResolveCustomClaimsMap_UsesValidatedCustomClaims(t *testing.T) {
	vc := &jwtvalidator.ValidatedClaims{
		CustomClaims: &sourceCustomClaims{Source: "validated"},
	}
	tokenString := makeTokenString(t, gojwt.MapClaims{"source": "token"})

	claims, err := ResolveCustomClaimsMap(vc, tokenString)
	require.NoError(t, err)
	require.Equal(t, "validated", claims["source"])
}

func TestResolveCustomClaimsMap_FallsBackToTokenPayloadWhenCustomClaimsMissing(t *testing.T) {
	now := time.Now()
	vc := &jwtvalidator.ValidatedClaims{}
	tokenString := makeTokenString(t, gojwt.MapClaims{
		"sub": "alice",
		"aud": "account",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"realm_access": map[string]any{
			"roles": []string{"connect-admin"},
		},
	})

	claims, err := ResolveCustomClaimsMap(vc, tokenString)
	require.NoError(t, err)
	require.Equal(t, "alice", claims["sub"])
	require.Equal(t, "account", claims["aud"])
	realmAccess, ok := claims["realm_access"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, []any{"connect-admin"}, realmAccess["roles"])
}

func TestResolveCustomClaimsMap_FallsBackToTokenPayloadWhenCustomClaimsMarshalFails(t *testing.T) {
	now := time.Now()
	vc := &jwtvalidator.ValidatedClaims{
		CustomClaims: &brokenCustomClaims{Bad: make(chan int)},
	}
	tokenString := makeTokenString(t, gojwt.MapClaims{
		"sub": "alice",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})

	claims, err := ResolveCustomClaimsMap(vc, tokenString)
	require.NoError(t, err)
	require.Equal(t, "alice", claims["sub"])
}

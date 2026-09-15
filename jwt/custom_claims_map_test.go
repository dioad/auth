package jwt

import (
	"context"
	"errors"
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

// arrayCustomClaims marshals to a JSON array rather than an object, so
// json.Unmarshal into map[string]any fails -- used to reach
// CustomClaimsMapFromValidatedClaims's unmarshal error path, distinct
// from brokenCustomClaims's marshal error path above.
type arrayCustomClaims struct{}

func (a *arrayCustomClaims) Validate(_ context.Context) error { return nil }
func (a *arrayCustomClaims) MarshalJSON() ([]byte, error)     { return []byte("[1,2,3]"), nil }

func TestCustomClaimsMapFromValidatedClaims_NilValidatedClaims(t *testing.T) {
	claims, err := CustomClaimsMapFromValidatedClaims(nil)
	require.NoError(t, err)
	require.Nil(t, claims)
}

func TestCustomClaimsMapFromValidatedClaims_NilCustomClaims(t *testing.T) {
	claims, err := CustomClaimsMapFromValidatedClaims(&jwtvalidator.ValidatedClaims{})
	require.NoError(t, err)
	require.Nil(t, claims)
}

func TestCustomClaimsMapFromValidatedClaims_Populated(t *testing.T) {
	vc := &jwtvalidator.ValidatedClaims{CustomClaims: &sourceCustomClaims{Source: "validated"}}

	claims, err := CustomClaimsMapFromValidatedClaims(vc)
	require.NoError(t, err)
	require.Equal(t, "validated", claims["source"])
}

func TestCustomClaimsMapFromValidatedClaims_MarshalError(t *testing.T) {
	vc := &jwtvalidator.ValidatedClaims{CustomClaims: &brokenCustomClaims{Bad: make(chan int)}}

	claims, err := CustomClaimsMapFromValidatedClaims(vc)
	require.Error(t, err)
	require.Nil(t, claims)
	// "marshal custom claims" alone is a substring of "unmarshal custom
	// claims" (the sibling error message a few lines down), so pin the full
	// wrapped message to actually distinguish the two paths.
	require.ErrorContains(t, err, "marshal custom claims: json: unsupported type: chan int")
	require.NotNil(t, errors.Unwrap(err), "the underlying marshal error must be unwrappable, not just interpolated")
}

func TestCustomClaimsMapFromValidatedClaims_UnmarshalError(t *testing.T) {
	vc := &jwtvalidator.ValidatedClaims{CustomClaims: &arrayCustomClaims{}}

	claims, err := CustomClaimsMapFromValidatedClaims(vc)
	require.Error(t, err)
	require.Nil(t, claims)
	require.ErrorContains(t, err, "unmarshal custom claims")
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

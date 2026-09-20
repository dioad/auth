package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateToken_KeyFuncNotConfigured pins the "key function not
// configured" error path. NewClient always derives a keyFunc from a
// jwksProvider it provisions itself, so this state can't be reached through
// the public constructor; it is only reachable by a Client with neither
// field set, which is why this is a white-box test.
func TestValidateToken_KeyFuncNotConfigured(t *testing.T) {
	endpoint, err := NewEndpoint("https://issuer.example")
	require.NoError(t, err)

	client := &Client{endpoint: endpoint}

	_, err = client.ValidateToken(t.Context(), "irrelevant-token", []string{"aud"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "key function not configured")
}

// TestValidateToken_RejectsInvalidSignatureAlgorithmConfig pins the
// "invalid validating signature algorithms" error path: an empty algorithm
// entry in the configured list must cause ValidateToken to fail before it
// attempts to construct a validator or touch the token at all.
func TestValidateToken_RejectsInvalidSignatureAlgorithmConfig(t *testing.T) {
	endpoint, err := NewEndpoint("https://issuer.example")
	require.NoError(t, err)

	client := NewClient(
		endpoint,
		WithKeyFunc(func(context.Context) (any, error) {
			require.Fail(t, "keyFunc must not be invoked when the algorithm config is invalid")
			return nil, nil
		}),
		WithValidatingSignatureAlgorithms([]jwtvalidator.SignatureAlgorithm{""}),
	)

	_, err = client.ValidateToken(t.Context(), "irrelevant-token", []string{"aud"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid validating signature algorithms")
}

// TestValidateToken_PropagatesUnderlyingValidationError pins the
// "error validating token" wrapping path: a token that fails the
// underlying jwt-middleware validation (here, a signature that doesn't
// match the configured key) must come back as an error, not a nil error
// with a zero-value/invalid claims result.
func TestValidateToken_PropagatesUnderlyingValidationError(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuer := "https://issuer.example"
	claims := jwtv5.MapClaims{
		"iss": issuer,
		"sub": "test-user",
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(signingKey)
	require.NoError(t, err)

	endpoint, err := NewEndpoint(issuer)
	require.NoError(t, err)
	client := NewClient(
		endpoint,
		WithKeyFunc(func(context.Context) (any, error) {
			return &wrongKey.PublicKey, nil
		}),
		WithValidatingSignatureAlgorithm(jwtvalidator.RS256),
	)

	claimsResult, err := client.ValidateToken(t.Context(), tokenString, []string{"test-audience"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "error validating token")
	assert.Nil(t, claimsResult)
}

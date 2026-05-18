package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/testutil"
)

// These tests use a mock OIDC identity provider (testutil.MockIdP) that serves
// a discovery document and JWKS endpoint locally. Each test creates a signed
// JWT with specific characteristics so that you can set breakpoints and step
// through the verification logic in GoLand.
//
// To debug a specific scenario:
//  1. Open this file in GoLand.
//  2. Click the gutter icon next to the test function or sub-test you want to
//     investigate.
//  3. Choose "Debug <TestName>".
//  4. Set breakpoints inside verifyTokenWithConfig, fetchJWKSKeys, decodeHeader,
//     or decodeClaims to inspect the verification flow.

// TestVerifyDebug_ValidToken verifies end-to-end that a correctly signed token
// passes verification against the mock IdP's JWKS endpoint.
func TestVerifyDebug_ValidToken(t *testing.T) {
	idp, err := testutil.NewMockIdP()
	require.NoError(t, err)
	t.Cleanup(idp.Close)

	tokenString := signToken(t, idp, jwt.MapClaims{
		"iss": idp.Issuer,
		"sub": "test-user",
		"aud": "test-client",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	// Decode and inspect header.
	header, err := decodeHeader(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "RS256", header["alg"])
	assert.Equal(t, "test-key", header["kid"])

	// Decode and inspect claims.
	claims, err := decodeClaims(tokenString)
	require.NoError(t, err)
	assert.Equal(t, idp.Issuer, claims["iss"])

	// Fetch JWKS keys and verify they match the token's kid.
	keySet, err := fetchJWKSKeys(idp.Issuer)
	require.NoError(t, err)
	require.NotEmpty(t, keySet.Keys, "JWKS should contain at least one key")
	assert.Equal(t, "test-key", keySet.Keys[0].KeyID)
	assert.Equal(t, "RS256", keySet.Keys[0].Algorithm)

	// Full verification — set a breakpoint here to step into verifyTokenWithConfig.
	err = verifyTokenWithConfig(t.Context(), tokenString, idp.Issuer, []string{"test-client"})
	require.NoError(t, err, "valid token should pass verification")
}

// TestVerifyDebug_ExpiredToken creates a token that expired in the past so you
// can debug how the validator reports expiry errors.
func TestVerifyDebug_ExpiredToken(t *testing.T) {
	idp, err := testutil.NewMockIdP()
	require.NoError(t, err)
	t.Cleanup(idp.Close)

	tokenString := signToken(t, idp, jwt.MapClaims{
		"iss": idp.Issuer,
		"sub": "test-user",
		"aud": "test-client",
		"exp": time.Now().Add(-time.Hour).Unix(), // expired 1 hour ago
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})

	// The signature is valid, but the token is expired.
	err = verifyTokenWithConfig(t.Context(), tokenString, idp.Issuer, []string{"test-client"})
	require.Error(t, err, "expired token should fail verification")
	assert.Contains(t, err.Error(), "validating token")
}

// TestVerifyDebug_WrongAudience creates a token with one audience but validates
// against a different audience, so you can debug audience mismatch errors.
func TestVerifyDebug_WrongAudience(t *testing.T) {
	idp, err := testutil.NewMockIdP()
	require.NoError(t, err)
	t.Cleanup(idp.Close)

	tokenString := signToken(t, idp, jwt.MapClaims{
		"iss": idp.Issuer,
		"sub": "test-user",
		"aud": "correct-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	err = verifyTokenWithConfig(t.Context(), tokenString, idp.Issuer, []string{"wrong-audience"})
	require.Error(t, err, "wrong audience should fail verification")
	assert.Contains(t, err.Error(), "validating token")
}

// TestVerifyDebug_WrongIssuer creates a valid token but verifies it against a
// different issuer URL, so you can debug issuer mismatch errors.
func TestVerifyDebug_WrongIssuer(t *testing.T) {
	idp, err := testutil.NewMockIdP()
	require.NoError(t, err)
	t.Cleanup(idp.Close)

	tokenString := signToken(t, idp, jwt.MapClaims{
		"iss": "https://wrong-issuer.example.com",
		"sub": "test-user",
		"aud": "test-client",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	// Use the real IdP URL for JWKS discovery, but the token claims a different issuer.
	err = verifyTokenWithConfig(t.Context(), tokenString, idp.Issuer, []string{"test-client"})
	require.Error(t, err, "wrong issuer should fail verification")
	assert.Contains(t, err.Error(), "validating token")
}

// TestVerifyDebug_HeaderAndKeyDetails verifies that the token header details
// and JWKS key details can be decoded and compared for debugging key mismatches.
func TestVerifyDebug_HeaderAndKeyDetails(t *testing.T) {
	idp, err := testutil.NewMockIdP()
	require.NoError(t, err)
	t.Cleanup(idp.Close)

	tokenString := signToken(t, idp, jwt.MapClaims{
		"iss": idp.Issuer,
		"sub": "debug-user",
		"aud": "debug-client",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	// Decode the JWT header.
	header, err := decodeHeader(tokenString)
	require.NoError(t, err)

	tokenAlg, _ := header["alg"].(string)
	tokenKid, _ := header["kid"].(string)

	t.Logf("Token header — alg: %s, kid: %s", tokenAlg, tokenKid)

	// Fetch JWKS and compare.
	keySet, err := fetchJWKSKeys(idp.Issuer)
	require.NoError(t, err)

	matchFound := false
	for i, key := range keySet.Keys {
		t.Logf("JWKS key %d — kid: %s, alg: %s, use: %s, type: %T",
			i+1, key.KeyID, key.Algorithm, key.Use, key.Key)

		if key.KeyID == tokenKid {
			matchFound = true
			assert.Equal(t, tokenAlg, key.Algorithm,
				"token algorithm should match JWKS key algorithm")
		}
	}
	assert.True(t, matchFound, "JWKS should contain a key matching the token's kid %q", tokenKid)

	// Decode claims for completeness.
	claims, err := decodeClaims(tokenString)
	require.NoError(t, err)

	prettyHeader, _ := json.MarshalIndent(header, "", "  ")
	prettyClaims, _ := json.MarshalIndent(claims, "", "  ")
	t.Logf("Full header:\n%s", prettyHeader)
	t.Logf("Full claims:\n%s", prettyClaims)
}

// TestVerifyDebug_VerifyTokenFullFlow exercises the top-level verifyToken
// function that auto-extracts issuer and audience from claims.
func TestVerifyDebug_VerifyTokenFullFlow(t *testing.T) {
	idp, err := testutil.NewMockIdP()
	require.NoError(t, err)
	t.Cleanup(idp.Close)

	tokenString := signToken(t, idp, jwt.MapClaims{
		"iss": idp.Issuer,
		"sub": "flow-user",
		"aud": "flow-client",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	// Set a breakpoint here to step into the full verify flow.
	err = verifyToken(t.Context(), tokenString)
	require.NoError(t, err, "full flow verification should succeed")
}

// TestVerifyDebug_RawToken decodes and optionally verifies a raw access token
// provided via the AUTH_DEBUG_TOKEN environment variable. This is useful for
// debugging real tokens from external identity providers.
//
// To use this test:
//  1. Set AUTH_DEBUG_TOKEN to the raw JWT string you want to inspect.
//  2. Optionally set AUTH_DEBUG_ISSUER to override the issuer for JWKS discovery
//     (defaults to the "iss" claim in the token).
//  3. Optionally set AUTH_DEBUG_AUDIENCE to override the expected audience
//     (defaults to the "aud" claim in the token).
//  4. Run or debug the test from GoLand.
//
// Example:
//
//	AUTH_DEBUG_TOKEN="eyJhbGci..." go test -run TestVerifyDebug_RawToken -v ./cmd/auth-debug/
//
// The test is automatically skipped when AUTH_DEBUG_TOKEN is not set, so it
// will never fail in CI or normal test runs.
func TestVerifyDebug_RawToken(t *testing.T) {
	rawToken := strings.TrimSpace(os.Getenv("AUTH_DEBUG_TOKEN"))
	if rawToken == "" {
		t.Skip("AUTH_DEBUG_TOKEN not set — skipping raw token debug test")
	}

	// Decode and display header.
	header, err := decodeHeader(rawToken)
	require.NoError(t, err, "decoding JWT header")

	prettyHeader, _ := json.MarshalIndent(header, "", "  ")
	t.Logf("JWT Header:\n%s", prettyHeader)

	tokenAlg, _ := header["alg"].(string)
	tokenKid, _ := header["kid"].(string)
	t.Logf("Header — alg: %s, kid: %s", tokenAlg, tokenKid)

	// Decode and display claims.
	claims, err := decodeClaims(rawToken)
	require.NoError(t, err, "decoding JWT claims")

	prettyClaims, _ := json.MarshalIndent(claims, "", "  ")
	t.Logf("JWT Claims:\n%s", prettyClaims)

	// Determine issuer for JWKS discovery.
	issuer := strings.TrimSpace(os.Getenv("AUTH_DEBUG_ISSUER"))
	if issuer == "" {
		iss, ok := claims["iss"].(string)
		require.True(t, ok, "token must contain an 'iss' claim or set AUTH_DEBUG_ISSUER")
		issuer = iss
	}
	t.Logf("Using issuer: %s", issuer)

	// Fetch and display JWKS keys.
	keySet, err := fetchJWKSKeys(issuer)
	require.NoError(t, err, "fetching JWKS from issuer %s", issuer)

	t.Logf("JWKS Keys (%d):", len(keySet.Keys))
	for i, key := range keySet.Keys {
		t.Logf("  Key %d — kid: %s, alg: %s, use: %s, type: %T",
			i+1, key.KeyID, key.Algorithm, key.Use, key.Key)

		if key.KeyID == tokenKid {
			t.Logf("  ✓ Key %d matches token kid %q", i+1, tokenKid)
			if key.Algorithm != tokenAlg {
				t.Logf("  ⚠ Algorithm mismatch: token=%s, key=%s", tokenAlg, key.Algorithm)
			}
		}
	}

	// Determine audience for verification.
	audience := strings.TrimSpace(os.Getenv("AUTH_DEBUG_AUDIENCE"))
	var audiences []string
	if audience != "" {
		audiences = []string{audience}
	} else {
		audiences = extractAudiences(claims)
	}
	t.Logf("Using audiences: %v", audiences)

	// Verify the token — set a breakpoint here to step into verification.
	err = verifyTokenWithConfig(t.Context(), rawToken, issuer, audiences)
	if err != nil {
		t.Logf("✗ Verification failed: %v", err)
		t.Logf("  Hint: check kid/alg match, token expiry, issuer, and audience")
		t.Fail()
	} else {
		t.Logf("✓ Token signature and claims verified successfully")
	}
}

// signToken creates a signed JWT using the mock IdP's private key with the
// given claims. The token header includes kid "test-key" matching the mock
// IdP's JWKS.
func signToken(t *testing.T, idp *testutil.MockIdP, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"

	tokenString, err := token.SignedString(idp.Key)
	require.NoError(t, err, "signing token should succeed")

	return tokenString
}

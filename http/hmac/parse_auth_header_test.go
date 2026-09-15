package hmac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAuthHeader_RejectsEmpty(t *testing.T) {
	_, _, err := parseAuthHeader("")
	require.Error(t, err)
	assert.ErrorContains(t, err, "missing auth header")
}

func TestParseAuthHeader_RejectsWrongScheme(t *testing.T) {
	_, _, err := parseAuthHeader("Bearer user:sig")
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid auth scheme")
}

func TestParseAuthHeader_RejectsMissingColon(t *testing.T) {
	_, _, err := parseAuthHeader(AuthScheme + " user-no-colon")
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid authorization header format")
}

func TestParseAuthHeader_ParsesPrincipalAndSignature(t *testing.T) {
	principal, signature, err := parseAuthHeader(AuthScheme + " test-user:abc123")
	require.NoError(t, err)
	assert.Equal(t, "test-user", principal)
	assert.Equal(t, "abc123", signature)
}

// TestParseAuthHeader_PreservesColonsWithinSignature is the regression test
// for SplitN's limit argument: the signature is split from the principal
// with SplitN(credentials, ":", 2) specifically so a signature value that
// itself contains colons is captured whole, not truncated at the first
// embedded colon.
func TestParseAuthHeader_PreservesColonsWithinSignature(t *testing.T) {
	principal, signature, err := parseAuthHeader(AuthScheme + " test-user:sig:with:colons")
	require.NoError(t, err)
	assert.Equal(t, "test-user", principal)
	assert.Equal(t, "sig:with:colons", signature)
}

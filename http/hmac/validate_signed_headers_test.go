package hmac

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRequestWithSignedHeaders(signedHeaders string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if signedHeaders != "" {
		r.Header.Set(DefaultSignedHeadersHeader, signedHeaders)
	}
	return r
}

func TestValidateSignedHeaders_NoConfigurationAllowsAnything(t *testing.T) {
	headers, err := validateSignedHeaders(newRequestWithSignedHeaders("X-Whatever"), nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"X-Whatever"}, headers)
}

func TestValidateSignedHeaders_RejectsMissingWhenConfigured(t *testing.T) {
	_, err := validateSignedHeaders(newRequestWithSignedHeaders(""), []string{"Content-Type"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "missing signed headers")
}

func TestValidateSignedHeaders_RejectsCountMismatch(t *testing.T) {
	_, err := validateSignedHeaders(newRequestWithSignedHeaders("Content-Type"), []string{"Content-Type", "X-Api-Key"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "signed headers do not match server configuration")
}

func TestValidateSignedHeaders_AcceptsExactMatch(t *testing.T) {
	headers, err := validateSignedHeaders(newRequestWithSignedHeaders("Content-Type,X-Api-Key"), []string{"Content-Type", "X-Api-Key"})
	require.NoError(t, err)
	assert.Equal(t, []string{"Content-Type", "X-Api-Key"}, headers)
}

// TestValidateSignedHeaders_RejectsMismatchNotJustFirstElement is the
// regression test for a loop-scope bug class: a client-declared header list
// that matches the server's configuration on its first element but
// diverges later must still be rejected. A loop that stops checking after
// the first element -- e.g. an accidental early break -- would let a
// second, mismatched header slip through as if it were signed correctly.
func TestValidateSignedHeaders_RejectsMismatchNotJustFirstElement(t *testing.T) {
	_, err := validateSignedHeaders(newRequestWithSignedHeaders("Content-Type,Wrong-Header"), []string{"Content-Type", "X-Api-Key"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "signed headers do not match server configuration")
}

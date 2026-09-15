package hmac

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type erroringReadCloser struct{}

func (erroringReadCloser) Read([]byte) (int, error) { return 0, errors.New("boom") }
func (erroringReadCloser) Close() error             { return nil }

func TestClientAuth_AddAuth_PropagatesBodyReadError(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://example.com/api", nil)
	require.NoError(t, err)
	req.Body = erroringReadCloser{}

	auth := ClientAuth{Config: ClientConfig{CommonConfig: CommonConfig{SharedKey: "secret"}, Principal: "user"}}
	err = auth.AddAuth(req)
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to read request body")
}

func TestClientAuth_AddAuth_SetsGetBodyWhenAbsent(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://example.com/api", bytes.NewBufferString("payload"))
	require.NoError(t, err)
	req.GetBody = nil

	auth := ClientAuth{Config: ClientConfig{CommonConfig: CommonConfig{SharedKey: "secret"}, Principal: "user"}}
	require.NoError(t, auth.AddAuth(req))

	require.NotNil(t, req.GetBody, "GetBody must be set so the request can be retried")
	rc, err := req.GetBody()
	require.NoError(t, err)
	body, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(body))
}

func TestClientAuth_AddAuth_DoesNotReplaceExistingGetBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://example.com/api", bytes.NewBufferString("payload"))
	require.NoError(t, err)

	called := false
	req.GetBody = func() (io.ReadCloser, error) {
		called = true
		return io.NopCloser(bytes.NewBufferString("caller-provided")), nil
	}

	auth := ClientAuth{Config: ClientConfig{CommonConfig: CommonConfig{SharedKey: "secret"}, Principal: "user"}}
	require.NoError(t, auth.AddAuth(req))

	rc, err := req.GetBody()
	require.NoError(t, err)
	body, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.True(t, called, "the caller-provided GetBody must be preserved, not replaced")
	assert.Equal(t, "caller-provided", string(body))
}

func TestClientAuth_AddAuth_OmitsSignedHeadersHeaderWhenNoneConfigured(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.com/api", nil)
	require.NoError(t, err)

	auth := ClientAuth{Config: ClientConfig{CommonConfig: CommonConfig{SharedKey: "secret"}, Principal: "user"}}
	require.NoError(t, auth.AddAuth(req))

	_, present := req.Header[DefaultSignedHeadersHeader]
	assert.False(t, present, "the signed-headers header must be omitted entirely when no headers are configured, not sent as empty")
}

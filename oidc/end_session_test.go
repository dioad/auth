package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/oidc"
)

// newEndSessionProvider serves a discovery document whose end_session
// endpoint answers with status, recording the form it receives.
func newEndSessionProvider(t *testing.T, status int, withEndpoint bool) (*httptest.Server, *url.Values) {
	t.Helper()

	received := &url.Values{}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		config := map[string]string{"issuer": srv.URL, "token_endpoint": srv.URL + "/token"}
		if withEndpoint {
			config["end_session_endpoint"] = srv.URL + "/logout"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(config)
	})
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		*received = r.PostForm
		w.WriteHeader(status)
	})
	return srv, received
}

func newEndSessionClient(t *testing.T, issuer string) *oidc.Client {
	t.Helper()
	endpoint, err := oidc.NewEndpoint(issuer)
	require.NoError(t, err)
	return oidc.NewClient(endpoint, oidc.WithClientIDAndSecret("console", "console-secret"))
}

func TestClient_EndSession_PostsRefreshTokenAndClientCredentials(t *testing.T) {
	srv, received := newEndSessionProvider(t, http.StatusNoContent, true)

	err := newEndSessionClient(t, srv.URL).EndSession(context.Background(), "refresh-123")

	require.NoError(t, err)
	assert.Equal(t, "refresh-123", received.Get("refresh_token"))
	assert.Equal(t, "console", received.Get("client_id"))
	assert.Equal(t, "console-secret", received.Get("client_secret"))
}

func TestClient_EndSession_Errors(t *testing.T) {
	t.Run("provider refuses", func(t *testing.T) {
		srv, _ := newEndSessionProvider(t, http.StatusBadRequest, true)
		err := newEndSessionClient(t, srv.URL).EndSession(context.Background(), "refresh-123")
		require.ErrorContains(t, err, "400")
	})

	t.Run("no end_session endpoint", func(t *testing.T) {
		srv, _ := newEndSessionProvider(t, http.StatusNoContent, false)
		err := newEndSessionClient(t, srv.URL).EndSession(context.Background(), "refresh-123")
		require.ErrorContains(t, err, "end session endpoint not available")
	})

	t.Run("no refresh token", func(t *testing.T) {
		srv, received := newEndSessionProvider(t, http.StatusNoContent, true)
		err := newEndSessionClient(t, srv.URL).EndSession(context.Background(), "")
		require.ErrorContains(t, err, "refresh token is required")
		assert.Empty(t, *received, "nothing should be sent without a refresh token")
	})
}

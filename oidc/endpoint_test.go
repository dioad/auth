package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCEndpoint_Discovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := OpenIDConfiguration{
				Issuer:                "http://example.com",
				AuthorizationEndpoint: "http://example.com/auth",
				TokenEndpoint:         "http://example.com/token",
			}
			if err := json.NewEncoder(w).Encode(config); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}))
	defer server.Close()

	endpoint, err := NewEndpoint(server.URL)
	require.NoError(t, err)

	config, err := endpoint.DiscoveredConfiguration()
	assert.NoError(t, err)
	assert.Equal(t, "http://example.com", config.Issuer)
	assert.Equal(t, "http://example.com/auth", config.AuthorizationEndpoint)
}

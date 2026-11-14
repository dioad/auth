package oidc_test

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/net/tls"
	"github.com/dioad/util"

	"github.com/dioad/auth/oidc"
)

// writeRootCA writes server's certificate to a PEM file and returns its path.
func writeRootCA(t *testing.T, server *httptest.Server) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

func TestNewIdentityClient_ZeroIdentityIsPlainClient(t *testing.T) {
	t.Parallel()

	service := newEchoAuthService(httptest.NewServer)
	t.Cleanup(service.Close)

	client, err := oidc.NewIdentityClient(t.Context(), oidc.ClientConfig{}, tls.ClientConfig{})
	require.NoError(t, err)
	assert.Equal(t, oidc.DefaultIdentityClientTimeout, client.Timeout)

	status, body, err := get(t.Context(), client, service.URL)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Empty(t, body, "a plain client must not send an Authorization header")
}

func TestNewIdentityClient_AuthenticatesAsIdentity(t *testing.T) {
	t.Parallel()

	provider := newTokenProvider(httptest.NewServer)
	t.Cleanup(provider.server.Close)
	service := newEchoAuthService(httptest.NewServer)
	t.Cleanup(service.Close)

	// The client must keep working after the context it was built with is
	// cancelled: tokens are fetched lazily, long after start-up.
	ctx, cancel := context.WithCancel(t.Context())
	client, err := oidc.NewIdentityClient(ctx, provider.identity(), tls.ClientConfig{}, oidc.WithTimeout(5*time.Second))
	require.NoError(t, err)
	cancel()
	assert.Equal(t, 5*time.Second, client.Timeout)

	for range 2 {
		status, body, err := get(t.Context(), client, service.URL)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "Bearer service-token", body)
	}
	assert.Equal(t, int32(1), provider.issued.Load(), "an unexpired token must be reused")
}

// TestNewIdentityClient_TLSConfigs covers which TLS config applies to which
// connection: target to the service being called, identity.TLSClient to the
// identity provider.
func TestNewIdentityClient_TLSConfigs(t *testing.T) {
	t.Parallel()

	provider := newTokenProvider(httptest.NewTLSServer)
	t.Cleanup(provider.server.Close)
	service := newEchoAuthService(httptest.NewTLSServer)
	t.Cleanup(service.Close)

	providerCA := tls.ClientConfig{RootCAFile: writeRootCA(t, provider.server)}
	serviceCA := tls.ClientConfig{RootCAFile: writeRootCA(t, service)}

	tests := []struct {
		name        string
		identityTLS tls.ClientConfig
		targetTLS   tls.ClientConfig
		wantErr     bool
	}{
		{name: "each connection trusts its own CA", identityTLS: providerCA, targetTLS: serviceCA},
		{name: "provider CA missing", targetTLS: serviceCA, wantErr: true},
		{name: "service CA missing", identityTLS: providerCA, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			identity := provider.identity()
			identity.TLSClient = tt.identityTLS

			client, err := oidc.NewIdentityClient(t.Context(), identity, tt.targetTLS)
			require.NoError(t, err)

			_, body, err := get(t.Context(), client, service.URL)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "Bearer service-token", body)
		})
	}
}

func TestNewIdentityClient_BaseTransportIsNotModified(t *testing.T) {
	t.Parallel()

	service := newEchoAuthService(httptest.NewTLSServer)
	t.Cleanup(service.Close)

	base := &http.Transport{MaxIdleConns: 7}
	client, err := oidc.NewIdentityClient(t.Context(), oidc.ClientConfig{},
		tls.ClientConfig{RootCAFile: writeRootCA(t, service)}, oidc.WithBaseTransport(base))
	require.NoError(t, err)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Equal(t, 7, transport.MaxIdleConns, "the client must be built from the given transport")
	assert.NotSame(t, base, transport)
	// Cloning a transport initialises its TLSClientConfig, so check the CA.
	if base.TLSClientConfig != nil {
		assert.Nil(t, base.TLSClientConfig.RootCAs, "the caller's transport must not be given the target's CA")
	}

	status, _, err := get(t.Context(), client, service.URL)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
}

func TestNewIdentityClient_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		identity oidc.ClientConfig
		target   tls.ClientConfig
		wantErr  error
	}{
		{
			name:     "identity without credentials",
			identity: oidc.ClientConfig{EndpointConfig: oidc.EndpointConfig{URL: "https://idp.example"}, ClientID: "billing-service"},
			wantErr:  oidc.ErrNoIdentity,
		},
		{
			name:   "unreadable target CA",
			target: tls.ClientConfig{RootCAFile: "/nonexistent/ca.pem"},
		},
		{
			name: "unreadable identity CA",
			identity: oidc.ClientConfig{
				EndpointConfig: oidc.EndpointConfig{URL: "https://idp.example"},
				ClientID:       "billing-service",
				ClientSecret:   *util.NewMaskedString("service-secret"),
				TLSClient:      tls.ClientConfig{RootCAFile: "/nonexistent/ca.pem"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, err := oidc.NewIdentityClient(t.Context(), tt.identity, tt.target)
			require.Error(t, err)
			assert.Nil(t, client)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

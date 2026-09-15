package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewClient_KeyFuncOnlyDoesNotCreateJWKSProvider covers the
// jwksProvider == nil && keyFunc == nil auto-provisioning guard: when a
// caller supplies WithKeyFunc alone, NewClient must not also build and
// attach a jwksProvider that nothing will use.
func TestNewClient_KeyFuncOnlyDoesNotCreateJWKSProvider(t *testing.T) {
	endpoint, err := NewEndpoint("https://issuer.example")
	require.NoError(t, err)

	called := false
	explicitKeyFunc := func(context.Context) (any, error) {
		called = true
		return "sentinel-key", nil
	}

	client := NewClient(endpoint, WithKeyFunc(explicitKeyFunc))

	assert.Nil(t, client.jwksProvider, "a jwksProvider must not be auto-created when an explicit keyFunc is already set")

	key, err := client.keyFunc(context.Background())
	require.NoError(t, err)
	assert.True(t, called, "the explicitly provided keyFunc must be preserved")
	assert.Equal(t, "sentinel-key", key)
}

// TestNewClient_JWKSProviderOnlyIsNotReplaced covers the companion guard at
// the jwksProvider == nil && keyFunc == nil check: when a caller supplies
// WithJWKSProvider alone, NewClient must use that exact provider instance,
// not silently discard it and build a fresh one from the endpoint URL.
func TestNewClient_JWKSProviderOnlyIsNotReplaced(t *testing.T) {
	issuerURL, err := url.Parse("https://issuer.example")
	require.NoError(t, err)
	customProvider, err := jwks.NewCachingProvider(jwks.WithIssuerURL(issuerURL))
	require.NoError(t, err)

	// A different endpoint URL than the provider's issuer: if NewClient ever
	// replaced customProvider with one auto-derived from the endpoint, this
	// test's identity check below would fail to catch it silently succeeding
	// against the wrong issuer.
	endpoint, err := NewEndpoint("https://different-issuer.example")
	require.NoError(t, err)

	client := NewClient(endpoint, WithJWKSProvider(customProvider))

	assert.Same(t, customProvider, client.jwksProvider, "an explicitly provided jwksProvider must not be replaced")
	require.NotNil(t, client.keyFunc, "keyFunc must be derived from the explicit jwksProvider")
}

// TestNewClient_ExplicitKeyFuncWinsOverJWKSProvider covers the keyFunc ==
// nil && jwksProvider != nil guard: when both WithKeyFunc and
// WithJWKSProvider are supplied, the explicit keyFunc must not be
// overwritten by the provider's KeyFunc.
func TestNewClient_ExplicitKeyFuncWinsOverJWKSProvider(t *testing.T) {
	issuerURL, err := url.Parse("https://issuer.example")
	require.NoError(t, err)
	provider, err := jwks.NewCachingProvider(jwks.WithIssuerURL(issuerURL))
	require.NoError(t, err)

	endpoint, err := NewEndpoint("https://issuer.example")
	require.NoError(t, err)

	called := false
	explicitKeyFunc := func(context.Context) (any, error) {
		called = true
		return "sentinel-key", nil
	}

	client := NewClient(endpoint, WithKeyFunc(explicitKeyFunc), WithJWKSProvider(provider))

	key, err := client.keyFunc(context.Background())
	require.NoError(t, err)
	assert.True(t, called, "the explicitly provided keyFunc must win over the JWKS provider's")
	assert.Equal(t, "sentinel-key", key)
}

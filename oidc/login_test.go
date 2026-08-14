package oidc_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/oidc"
	"github.com/dioad/auth/testutil"
)

// countingDoer wraps http.DefaultClient and counts requests it handles, so
// tests can observe whether a ClientOpt passed through NewClientFromConfig
// was actually applied to the constructed Client.
type countingDoer struct {
	calls int
}

func (d *countingDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls++
	return http.DefaultClient.Do(req)
}

// TestNewClientFromConfig_AppliesAdditionalOpts confirms opts passed to
// NewClientFromConfig (beyond the config-derived client ID/secret) are
// actually applied to the constructed Client, not silently dropped - the gap
// that motivated widening its signature.
func TestNewClientFromConfig_AppliesAdditionalOpts(t *testing.T) {
	idp, err := testutil.NewMockIdP()
	require.NoError(t, err)
	defer idp.Close()

	config := &oidc.ClientConfig{
		EndpointConfig: oidc.EndpointConfig{URL: idp.Issuer},
		ClientID:       "test-client",
	}

	doer := &countingDoer{}
	client, err := oidc.NewClientFromConfig(config, oidc.WithHTTPClient(doer))
	require.NoError(t, err)

	ctx := context.Background()
	_, err = client.AuthorizationCodeToken(ctx, "mock-code", "http://localhost/callback")
	require.NoError(t, err)

	assert.Greater(t, doer.calls, 0, "custom HTTPDoer passed via NewClientFromConfig's opts should have handled the token exchange request")
}

func TestOIDCLoginFlow(t *testing.T) {
	idp, err := testutil.NewMockIdP()
	require.NoError(t, err)
	defer idp.Close()

	config := &oidc.ClientConfig{
		EndpointConfig: oidc.EndpointConfig{
			URL: idp.Issuer,
		},
		ClientID: "test-client",
	}

	client, err := oidc.NewClientFromConfig(config)
	require.NoError(t, err)

	// Simulate authorization code flow
	ctx := context.Background()
	authURL, err := client.AuthorizationCodeRedirectFlow(ctx, "state", []string{"openid"}, "http://localhost/callback")
	assert.NoError(t, err)
	assert.Contains(t, authURL, idp.Issuer)
	assert.Contains(t, authURL, "state")

	// Token exchange (simulated with the mock)
	token, err := client.AuthorizationCodeToken(ctx, "mock-code", "http://localhost/callback")
	assert.NoError(t, err)
	assert.NotEmpty(t, token.AccessToken)
	assert.NotEmpty(t, token.Extra("id_token"))

	// Validation
	validatedClaims, err := client.ValidateToken(ctx, token.AccessToken, []string{"test-client"})
	if assert.NoError(t, err) {
		assert.Equal(t, "test-user", validatedClaims.RegisteredClaims.Subject)
	}
}

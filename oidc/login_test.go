package oidc_test

import (
	"context"
	"testing"

	"github.com/dioad/auth/oidc"
	"github.com/dioad/auth/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

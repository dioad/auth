package authctx

import (
	"context"
	"testing"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticatedPrincipalFromContext_Empty(t *testing.T) {
	principal, ok := AuthenticatedPrincipalFromContext(context.Background())
	assert.False(t, ok)
	assert.Empty(t, principal)
}

func TestAuthenticatedPrincipalFromContext_RoundTrip(t *testing.T) {
	ctx := ContextWithAuthenticatedPrincipal(context.Background(), "alice")

	principal, ok := AuthenticatedPrincipalFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "alice", principal)
}

func TestAuthenticatedRegisteredClaimsFromContext_Empty(t *testing.T) {
	claims, ok := AuthenticatedRegisteredClaimsFromContext(context.Background())
	assert.False(t, ok)
	assert.Zero(t, claims)
}

func TestAuthenticatedRegisteredClaimsFromContext_RoundTrip(t *testing.T) {
	want := jwtvalidator.RegisteredClaims{Subject: "alice", Issuer: "https://issuer.example"}
	ctx := ContextWithAuthenticatedRegisteredClaims(context.Background(), want)

	got, ok := AuthenticatedRegisteredClaimsFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, want, got)
}

func TestAuthenticatedCustomClaimsFromContext_Empty(t *testing.T) {
	claims, ok := AuthenticatedCustomClaimsFromContext(context.Background())
	assert.False(t, ok)
	assert.Nil(t, claims)
}

func TestAuthenticatedCustomClaimsFromContext_RoundTrip(t *testing.T) {
	want := map[string]any{"role": "admin"}
	ctx := ContextWithAuthenticatedCustomClaims(context.Background(), want)

	got, ok := AuthenticatedCustomClaimsFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, want, got)
}

func TestGitHubUserInfoFromContext_Empty(t *testing.T) {
	assert.Nil(t, GitHubUserInfoFromContext(context.Background()))
}

func TestGitHubUserInfoFromContext_RoundTrip(t *testing.T) {
	want := &GitHubUserInfo{
		Login:                "octocat",
		Name:                 "The Octocat",
		PrimaryEmail:         "octocat@example.com",
		PrimaryEmailVerified: true,
		Company:              "GitHub",
		WebSite:              "https://github.com",
		Location:             "San Francisco",
		PlanName:             "pro",
	}
	ctx := NewContextWithGitHubUserInfo(context.Background(), want)

	got := GitHubUserInfoFromContext(ctx)
	require.NotNil(t, got)
	assert.Equal(t, want, got)
}

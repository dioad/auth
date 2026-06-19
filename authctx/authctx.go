// Package authctx defines context keys and accessor functions for credentials
// stored in a request context by authentication middleware.
//
// This package is a domain-level leaf: it imports no auth sub-packages, so any
// package in the auth module can import it without creating import cycles.
package authctx

import (
	"context"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
)

type principalContextKey struct{}
type registeredClaimsContextKey struct{}
type customClaimsContextKey struct{}

// ContextWithAuthenticatedPrincipal stores the authenticated principal on the context.
func ContextWithAuthenticatedPrincipal(ctx context.Context, principal string) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

// AuthenticatedPrincipalFromContext extracts the authenticated principal from context.
func AuthenticatedPrincipalFromContext(ctx context.Context) (string, bool) {
	val := ctx.Value(principalContextKey{})
	if val == nil {
		return "", false
	}
	principal, ok := val.(string)
	return principal, ok
}

// ContextWithAuthenticatedRegisteredClaims stores the authenticated claims on the context.
func ContextWithAuthenticatedRegisteredClaims(ctx context.Context, claims jwtvalidator.RegisteredClaims) context.Context {
	return context.WithValue(ctx, registeredClaimsContextKey{}, claims)
}

// AuthenticatedRegisteredClaimsFromContext extracts the authenticated claims from context.
func AuthenticatedRegisteredClaimsFromContext(ctx context.Context) (jwtvalidator.RegisteredClaims, bool) {
	val := ctx.Value(registeredClaimsContextKey{})
	if val == nil {
		return jwtvalidator.RegisteredClaims{}, false
	}
	claims, ok := val.(jwtvalidator.RegisteredClaims)
	return claims, ok
}

// ContextWithAuthenticatedCustomClaims stores the authenticated claims on the context.
func ContextWithAuthenticatedCustomClaims(ctx context.Context, claims map[string]any) context.Context {
	return context.WithValue(ctx, customClaimsContextKey{}, claims)
}

// AuthenticatedCustomClaimsFromContext extracts the authenticated claims from context.
func AuthenticatedCustomClaimsFromContext(ctx context.Context) (map[string]any, bool) {
	val := ctx.Value(customClaimsContextKey{})
	if val == nil {
		return nil, false
	}
	claims, ok := val.(map[string]any)
	return claims, ok
}

// GitHubUserInfo contains information about a GitHub user.
type GitHubUserInfo struct {
	Login                string
	Name                 string
	PrimaryEmail         string
	PrimaryEmailVerified bool
	Company              string
	WebSite              string
	Location             string
	PlanName             string
}

type githubUserInfoContextKey struct{}

// NewContextWithGitHubUserInfo returns a new context with the provided GitHub user info.
func NewContextWithGitHubUserInfo(ctx context.Context, userInfo *GitHubUserInfo) context.Context {
	return context.WithValue(ctx, githubUserInfoContextKey{}, userInfo)
}

// GitHubUserInfoFromContext returns the GitHub user info from the provided context.
// It returns nil if no user info is found.
func GitHubUserInfoFromContext(ctx context.Context) *GitHubUserInfo {
	val := ctx.Value(githubUserInfoContextKey{})
	if val != nil {
		return val.(*GitHubUserInfo)
	}
	return nil
}

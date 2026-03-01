package oidc

import (
	"context"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

type oidcUserContext struct{}
type authTokenContext struct{}

// ContextWithOIDCUserInfo returns a new context with the provided OIDC user info.
func ContextWithOIDCUserInfo(ctx context.Context, userInfo *goth.User) context.Context {
	return context.WithValue(ctx, oidcUserContext{}, userInfo)
}

// OIDCUserInfoFromContext returns the OIDC user info from the provided context.
// It returns nil if no user info is found.
func OIDCUserInfoFromContext(ctx context.Context) *goth.User {
	val := ctx.Value(oidcUserContext{})
	if val != nil {
		return val.(*goth.User)
	}
	return nil
}

// ContextWithAccessToken returns a new context with the provided access token.
func ContextWithAccessToken(ctx context.Context, token *oauth2.Token) context.Context {
	return context.WithValue(ctx, authTokenContext{}, token)
}

// AccessTokenFromContext returns the access token from the provided context.
// It returns a nil value if no token is found.
func AccessTokenFromContext(ctx context.Context) *oauth2.Token {
	val := ctx.Value(authTokenContext{})
	if val != nil {
		if token, ok := val.(*oauth2.Token); ok {
			return token
		}
	}
	return nil
}

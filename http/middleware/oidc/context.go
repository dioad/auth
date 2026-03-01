package oidc

import (
	"context"

	"github.com/markbates/goth"
)

type oidcUserContext struct{}

// ContextWithOIDCUserInfo returns a new context with the provided OIDC user info.
func ContextWithOIDCUserInfo(ctx context.Context, userInfo *goth.User) context.Context {
	return context.WithValue(ctx, oidcUserContext{}, userInfo)
}

// OIDCUserInfoFromContext returns the OIDC user info from the provided context.
func OIDCUserInfoFromContext(ctx context.Context) *goth.User {
	val := ctx.Value(oidcUserContext{})
	if val != nil {
		return val.(*goth.User)
	}
	return nil
}

type authTokenContext struct{}

func ContextWithAccessToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, authTokenContext{}, token)
}

func AccessTokenFromContext(ctx context.Context) string {
	val := ctx.Value(authTokenContext{})
	if val != nil {
		if token, ok := val.(string); ok {
			return token
		}
	}
	return ""
}

package context

import (
	"context"
)

type principalContextKey struct{}

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

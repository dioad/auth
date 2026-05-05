package oidc

import (
	"context"

	"github.com/dioad/auth/jwt"
	"github.com/dioad/auth/oidc/flyio"
)

// OIDCClaimsFromContext extracts OIDC claims from the request context.
// This is kept for backward compatibility and error reporting.
// For principal extraction, use service.PrincipalExtractor instead.
func ClaimsFromContext(ctx context.Context) any {
	if claims := jwt.CustomClaimsFromContext[*IntrospectionResponse](ctx); claims != nil {
		return claims
	}

	if flyIOClaims := jwt.CustomClaimsFromContext[*flyio.Claims](ctx); flyIOClaims != nil {
		return flyIOClaims
	}

	return nil
}

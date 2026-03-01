// Package jwt provides helpers for validating JSON Web Tokens (JWT) and composing claim predicates.
package jwt

import (
	"context"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/golang-jwt/jwt/v5"
)

// TokenValidator defines the interface for validating tokens.
type TokenValidator interface {
	ValidateToken(ctx context.Context, tokenString string) (any, error)
	String() string
}

// RegisteredClaims is an alias for the standard JWT registered claims.
type RegisteredClaims = jwt.RegisteredClaims

// CustomClaimsFromContext extracts custom claims from the context.
func CustomClaimsFromContext[T any](ctx context.Context) T {
	val := ctx.Value(jwtmiddleware.ContextKey{})
	if val == nil {
		var zero T
		return zero
	}
	claims, ok := val.(T)
	if !ok {
		var zero T
		return zero
	}
	return claims
}

// RegisteredClaimsFromContext extracts registered claims from the context.
func RegisteredClaimsFromContext(ctx context.Context) *jwt.RegisteredClaims {
	return CustomClaimsFromContext[*jwt.RegisteredClaims](ctx)
}

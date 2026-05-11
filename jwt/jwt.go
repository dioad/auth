// Package jwt provides helpers for validating JSON Web Tokens (JWT) and composing claim predicates.
package jwt

import (
	"context"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/golang-jwt/jwt/v5"
)

// TokenValidator defines the interface for validating tokens.
type TokenValidator interface {
	ValidateToken(ctx context.Context, tokenString string) (any, error)
	String() string
}

// RegisteredClaims is an alias for the standard JWT registered claims.
type RegisteredClaims = jwt.RegisteredClaims

// ValidatedClaimsFromContext returns the *jwtvalidator.ValidatedClaims stored in ctx by
// the JWT middleware. Returns nil when no validated claims are present.
func ValidatedClaimsFromContext(ctx context.Context) *jwtvalidator.ValidatedClaims {
	vc, err := jwtmiddleware.GetClaims[*jwtvalidator.ValidatedClaims](ctx)
	if err != nil {
		return nil
	}
	return vc
}

// CustomClaimsFromContext extracts provider-specific custom claims from ctx.
//
// The JWT middleware stores a *jwtvalidator.ValidatedClaims wrapper in the context.
// This function first attempts to unwrap the custom claims from that wrapper
// (ValidatedClaims.CustomClaims), and falls back to a direct type assertion for
// callers (e.g. unit tests) that store claims directly.
func CustomClaimsFromContext[T any](ctx context.Context) T {
	// Primary path: unwrap from the ValidatedClaims wrapper set by the JWT middleware.
	if vc := ValidatedClaimsFromContext(ctx); vc != nil {
		if t, ok := vc.CustomClaims.(T); ok {
			return t
		}
	}

	// Fallback: direct type assertion, for unit tests or callers that set claims directly.
	val, err := jwtmiddleware.GetClaims[T](ctx)
	if err != nil {
		var zero T
		return zero
	}
	return val
}

// RegisteredClaimsFromContext returns the registered JWT claims from ctx.
//
// When the JWT middleware is in use, claims are stored as *jwtvalidator.ValidatedClaims;
// this function extracts the RegisteredClaims from that wrapper. For unit tests or legacy
// callers that store *jwt.RegisteredClaims directly, it falls back to a direct assertion.
func RegisteredClaimsFromContext(ctx context.Context) *jwt.RegisteredClaims {
	// Primary path: extract from ValidatedClaims wrapper set by the JWT middleware.
	if vc := ValidatedClaimsFromContext(ctx); vc != nil {
		rc := vc.RegisteredClaims
		// Map validator.RegisteredClaims to jwt.RegisteredClaims (the two types differ slightly)
		jwtRC := &jwt.RegisteredClaims{
			Issuer:   rc.Issuer,
			Subject:  rc.Subject,
			Audience: rc.Audience,
			ID:       rc.ID,
		}
		// Convert int64 timestamps to NumericDate pointers
		if rc.NotBefore > 0 {
			jwtRC.NotBefore = jwt.NewNumericDate(time.Unix(rc.NotBefore, 0))
		}
		if rc.IssuedAt > 0 {
			jwtRC.IssuedAt = jwt.NewNumericDate(time.Unix(rc.IssuedAt, 0))
		}
		if rc.Expiry > 0 {
			jwtRC.ExpiresAt = jwt.NewNumericDate(time.Unix(rc.Expiry, 0))
		}
		return jwtRC
	}

	// Fallback: direct assertion for tests or callers that store claims directly.
	return CustomClaimsFromContext[*jwt.RegisteredClaims](ctx)
}

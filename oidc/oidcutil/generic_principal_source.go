package oidcutil

import (
	"context"

	"github.com/dioad/auth/authctx"
	"github.com/dioad/auth/jwt"
	"github.com/dioad/auth/mapper"
)

// ClaimsMapper is implemented by provider-specific typed OIDC claims types
// (e.g. aws.Claims, flyio.Claims, githubactions.Claims) so the Generic*
// helpers below can flatten typed claims into the map[string]any shape
// ClaimRoleMapper rules and PrincipalSource.Claims callers expect.
type ClaimsMapper interface {
	// ClaimsMap returns the typed claims as a flat map, seeded with any
	// canonical keys (e.g. "username") the provider wants alongside its raw
	// claim names. subject is the token's registered "sub" claim (may be
	// empty); implementations that don't derive "username" from it can
	// ignore the parameter.
	ClaimsMap(subject string) map[string]any
}

// These generic helpers implement the typed-path/generic-fallback-path
// pattern common to every OIDC PrincipalSource in this module: prefer claims
// already typed into the request context by a provider-specific JWT
// validator, and otherwise fingerprint the generic claims map (via
// hasValidClaims) to confirm a token validated by a non-typed JWT middleware
// actually belongs to this provider before extracting anything from it.
//
// T is always *C; the two-parameter shape is the standard Go idiom for
// requiring a pointer-to-C type that also implements an interface — a plain
// C-constrained-by-interface parameter can't be compared to nil inside a
// generic function body, and jwt.CustomClaimsFromContext's zero value for a
// "not present" result is a nil pointer.
//
// Each provider's PrincipalSource keeps its own concrete, zero-value-friendly
// struct type (just a RoleMapper field) and delegates its method bodies to
// these functions, so the exported API and zero-value construction pattern
// (&aws.PrincipalSource{}) are unchanged.

// GenericExtract returns the principal subject from ctx for provider C/T.
func GenericExtract[C any, T interface {
	*C
	ClaimsMapper
}](ctx context.Context, hasValidClaims func(claims map[string]any) bool) (string, error) {
	if claims := jwt.CustomClaimsFromContext[T](ctx); claims != nil {
		registered := jwt.RegisteredClaimsFromContext(ctx)
		if registered == nil {
			return "", nil
		}
		return registered.Subject, nil
	}

	custom, ok := authctx.AuthenticatedCustomClaimsFromContext(ctx)
	if !ok || !hasValidClaims(custom) {
		return "", nil
	}
	if principal, ok := authctx.AuthenticatedPrincipalFromContext(ctx); ok && principal != "" {
		return principal, nil
	}
	if sub, ok := custom["sub"].(string); ok && sub != "" {
		return sub, nil
	}
	return "", nil
}

// GenericIsService reports whether ctx carries a valid token for provider
// C/T, on either the typed or generic-fallback path.
func GenericIsService[C any, T interface {
	*C
	ClaimsMapper
}](ctx context.Context, hasValidClaims func(claims map[string]any) bool) bool {
	if jwt.CustomClaimsFromContext[T](ctx) != nil {
		return true
	}
	custom, _ := authctx.AuthenticatedCustomClaimsFromContext(ctx)
	return hasValidClaims(custom)
}

// GenericClaims returns the typed claims flattened via ClaimsMap on the typed
// path, or fallback(ctx, custom) on the generic-fallback path once custom has
// been confirmed valid by hasValidClaims. Returns an empty map when neither
// path yields claims.
func GenericClaims[C any, T interface {
	*C
	ClaimsMapper
}](ctx context.Context, hasValidClaims func(claims map[string]any) bool, fallback func(ctx context.Context, custom map[string]any) map[string]any) map[string]any {
	if claims := jwt.CustomClaimsFromContext[T](ctx); claims != nil {
		var subject string
		if registered := jwt.RegisteredClaimsFromContext(ctx); registered != nil {
			subject = registered.Subject
		}
		return claims.ClaimsMap(subject)
	}

	custom, ok := authctx.AuthenticatedCustomClaimsFromContext(ctx)
	if !ok || !hasValidClaims(custom) {
		return make(map[string]any)
	}
	return fallback(ctx, custom)
}

// GenericRoles maps claims via roleMapper, or returns nil when roleMapper is
// nil.
func GenericRoles(roleMapper mapper.Mapper, claims map[string]any) []string {
	if roleMapper == nil {
		return nil
	}
	return roleMapper.MapRoles(claims)
}

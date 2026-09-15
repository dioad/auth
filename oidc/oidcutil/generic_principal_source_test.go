package oidcutil_test

import (
	"context"
	"testing"

	"github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/authctx"
	"github.com/dioad/auth/oidc/oidcutil"
)

// stubClaims is a minimal oidcutil.ClaimsMapper used to exercise the typed
// path of the Generic* helpers without depending on a real provider package.
type stubClaims struct {
	Foo string
}

func (c *stubClaims) ClaimsMap(subject string) map[string]any {
	return map[string]any{"foo": c.Foo, "subject": subject}
}

func (c *stubClaims) Validate(context.Context) error { return nil }

type stubMapper struct {
	roles []string
}

func (m stubMapper) MapRoles(map[string]any) []string {
	return m.roles
}

// typedContext simulates the context produced by a JWT middleware configured
// with a provider-specific validator: a *jwtvalidator.ValidatedClaims wrapper
// carrying both registered and typed custom claims.
func typedContext(subject string, custom *stubClaims) context.Context {
	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{Subject: subject},
		CustomClaims:     custom,
	}
	return core.SetClaims(context.Background(), vc)
}

const markerKey = "marker"

func hasMarker(claims map[string]any) bool {
	return oidcutil.HasNonEmptyString(claims, markerKey)
}

func TestGenericRoles_NilMapper(t *testing.T) {
	assert.Nil(t, oidcutil.GenericRoles(nil, map[string]any{"a": "b"}))
}

func TestGenericRoles_DelegatesToMapper(t *testing.T) {
	roles := oidcutil.GenericRoles(stubMapper{roles: []string{"admin", "viewer"}}, map[string]any{"a": "b"})
	assert.Equal(t, []string{"admin", "viewer"}, roles)
}

func TestGenericExtract_TypedPath(t *testing.T) {
	ctx := typedContext("alice", &stubClaims{Foo: "bar"})

	principal, err := oidcutil.GenericExtract[stubClaims](ctx, hasMarker)
	require.NoError(t, err)
	assert.Equal(t, "alice", principal)
}

func TestGenericExtract_GenericFallbackPath_PrefersAuthenticatedPrincipal(t *testing.T) {
	ctx := authctx.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{markerKey: "present", "sub": "sub-claim-value"})
	ctx = authctx.ContextWithAuthenticatedPrincipal(ctx, "principal-from-context")

	principal, err := oidcutil.GenericExtract[stubClaims](ctx, hasMarker)
	require.NoError(t, err)
	assert.Equal(t, "principal-from-context", principal)
}

func TestGenericExtract_GenericFallbackPath_FallsBackToSubClaim(t *testing.T) {
	ctx := authctx.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{markerKey: "present", "sub": "sub-claim-value"})

	principal, err := oidcutil.GenericExtract[stubClaims](ctx, hasMarker)
	require.NoError(t, err)
	assert.Equal(t, "sub-claim-value", principal)
}

// TestGenericExtract_TypedPath_WithoutRegisteredClaims covers the typed
// path's own "no registered claims" guard: claims stored directly via the
// fallback context key (bypassing the *ValidatedClaims wrapper) satisfy the
// typed CustomClaims lookup but leave RegisteredClaimsFromContext with
// nothing to find, so extraction must return an empty principal with no
// error rather than panicking on a nil registered-claims dereference.
func TestGenericExtract_TypedPath_WithoutRegisteredClaims(t *testing.T) {
	ctx := core.SetClaims(context.Background(), &stubClaims{Foo: "bar"})

	principal, err := oidcutil.GenericExtract[stubClaims](ctx, hasMarker)
	require.NoError(t, err)
	assert.Empty(t, principal)
}

// TestGenericExtract_GenericFallbackPath_IgnoresEmptyAuthenticatedPrincipal
// verifies an authenticated-principal context value that is present but
// empty is treated the same as absent, falling through to the sub-claim
// check rather than being returned as the principal.
func TestGenericExtract_GenericFallbackPath_IgnoresEmptyAuthenticatedPrincipal(t *testing.T) {
	ctx := authctx.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{markerKey: "present", "sub": "sub-claim-value"})
	ctx = authctx.ContextWithAuthenticatedPrincipal(ctx, "")

	principal, err := oidcutil.GenericExtract[stubClaims](ctx, hasMarker)
	require.NoError(t, err)
	assert.Equal(t, "sub-claim-value", principal, "an empty authenticated principal must not shadow the sub-claim fallback")
}

// TestGenericExtract_GenericFallbackPath_IgnoresEmptySubClaim verifies a
// "sub" claim that is present but empty is not returned as the principal.
func TestGenericExtract_GenericFallbackPath_IgnoresEmptySubClaim(t *testing.T) {
	ctx := authctx.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{markerKey: "present", "sub": ""})

	principal, err := oidcutil.GenericExtract[stubClaims](ctx, hasMarker)
	require.NoError(t, err)
	assert.Empty(t, principal)
}

func TestGenericExtract_GenericFallbackPath_RejectsInvalidClaims(t *testing.T) {
	ctx := authctx.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{"sub": "sub-claim-value"})

	principal, err := oidcutil.GenericExtract[stubClaims](ctx, hasMarker)
	require.NoError(t, err)
	assert.Empty(t, principal)
}

func TestGenericExtract_NoClaims(t *testing.T) {
	principal, err := oidcutil.GenericExtract[stubClaims](context.Background(), hasMarker)
	require.NoError(t, err)
	assert.Empty(t, principal)
}

func TestGenericIsService_TypedPath(t *testing.T) {
	ctx := typedContext("alice", &stubClaims{Foo: "bar"})
	assert.True(t, oidcutil.GenericIsService[stubClaims](ctx, hasMarker))
}

func TestGenericIsService_GenericFallbackPath(t *testing.T) {
	valid := authctx.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{markerKey: "present"})
	assert.True(t, oidcutil.GenericIsService[stubClaims](valid, hasMarker))

	invalid := authctx.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{})
	assert.False(t, oidcutil.GenericIsService[stubClaims](invalid, hasMarker))

	assert.False(t, oidcutil.GenericIsService[stubClaims](context.Background(), hasMarker))
}

func TestGenericClaims_TypedPath(t *testing.T) {
	ctx := typedContext("alice", &stubClaims{Foo: "bar"})

	claims := oidcutil.GenericClaims[stubClaims](ctx, hasMarker, func(context.Context, map[string]any) map[string]any {
		t.Fatal("fallback must not be called when the typed path has claims")
		return nil
	})
	assert.Equal(t, map[string]any{"foo": "bar", "subject": "alice"}, claims)
}

func TestGenericClaims_GenericFallbackPath(t *testing.T) {
	custom := map[string]any{markerKey: "present", "raw": "value"}
	ctx := authctx.ContextWithAuthenticatedCustomClaims(context.Background(), custom)

	var gotCtx context.Context
	var gotCustom map[string]any
	claims := oidcutil.GenericClaims[stubClaims](ctx, hasMarker, func(fbCtx context.Context, fbCustom map[string]any) map[string]any {
		gotCtx = fbCtx
		gotCustom = fbCustom
		return map[string]any{"mapped": "result"}
	})

	assert.Equal(t, ctx, gotCtx)
	assert.Equal(t, custom, gotCustom)
	assert.Equal(t, map[string]any{"mapped": "result"}, claims)
}

func TestGenericClaims_InvalidClaimsReturnsEmptyMap(t *testing.T) {
	ctx := authctx.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{"raw": "value"})

	claims := oidcutil.GenericClaims[stubClaims](ctx, hasMarker, func(context.Context, map[string]any) map[string]any {
		t.Fatal("fallback must not be called when claims are invalid")
		return nil
	})
	assert.Equal(t, map[string]any{}, claims)
}

func TestGenericClaims_NoClaimsReturnsEmptyMap(t *testing.T) {
	claims := oidcutil.GenericClaims[stubClaims](context.Background(), hasMarker, func(context.Context, map[string]any) map[string]any {
		t.Fatal("fallback must not be called when no claims are present")
		return nil
	})
	assert.Equal(t, map[string]any{}, claims)
}

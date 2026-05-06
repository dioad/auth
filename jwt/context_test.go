package jwt

import (
	"context"
	"testing"

	"github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCustomClaims is a stub custom claims type used in tests.
type testCustomClaims struct {
	Role string `json:"role"`
}

func (t *testCustomClaims) Validate(_ context.Context) error { return nil }

// middlewareContext simulates the context produced by the JWT middleware: it stores a
// *jwtvalidator.ValidatedClaims wrapping both registered and custom claims.
func middlewareContext(subject string, custom jwtvalidator.CustomClaims) context.Context {
	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: subject,
			Issuer:  "test-issuer",
		},
		CustomClaims: custom,
	}
	return core.SetClaims(context.Background(), vc)
}

// TestValidatedClaimsFromContext_RealMiddlewarePath verifies that ValidatedClaimsFromContext
// returns the wrapped claims stored by the JWT middleware.
func TestValidatedClaimsFromContext_RealMiddlewarePath(t *testing.T) {
	ctx := middlewareContext("alice", &testCustomClaims{Role: "admin"})
	vc := ValidatedClaimsFromContext(ctx)
	require.NotNil(t, vc)
	assert.Equal(t, "alice", vc.RegisteredClaims.Subject)
}

// TestValidatedClaimsFromContext_Empty returns nil when no claims are set.
func TestValidatedClaimsFromContext_Empty(t *testing.T) {
	assert.Nil(t, ValidatedClaimsFromContext(context.Background()))
}

// TestRegisteredClaimsFromContext_RealMiddlewarePath verifies that Subject is extracted
// from the ValidatedClaims wrapper set by the JWT middleware (not a direct *RegisteredClaims).
func TestRegisteredClaimsFromContext_RealMiddlewarePath(t *testing.T) {
	ctx := middlewareContext("bob", nil)
	rc := RegisteredClaimsFromContext(ctx)
	require.NotNil(t, rc)
	assert.Equal(t, "bob", rc.Subject)
	assert.Equal(t, "test-issuer", rc.Issuer)
}

// TestRegisteredClaimsFromContext_DirectStoreFallback verifies that the fallback path works
// for callers (e.g. unit tests) that store *jwt.RegisteredClaims directly.
func TestRegisteredClaimsFromContext_DirectStoreFallback(t *testing.T) {
	direct := &gojwt.RegisteredClaims{Subject: "charlie"}
	ctx := core.SetClaims(context.Background(), direct)
	rc := RegisteredClaimsFromContext(ctx)
	require.NotNil(t, rc)
	assert.Equal(t, "charlie", rc.Subject)
}

// TestRegisteredClaimsFromContext_Empty returns nil when no claims are set.
func TestRegisteredClaimsFromContext_Empty(t *testing.T) {
	assert.Nil(t, RegisteredClaimsFromContext(context.Background()))
}

// TestCustomClaimsFromContext_RealMiddlewarePath verifies that provider-specific custom
// claims can be unwrapped from the ValidatedClaims wrapper.
func TestCustomClaimsFromContext_RealMiddlewarePath(t *testing.T) {
	ctx := middlewareContext("dave", &testCustomClaims{Role: "editor"})
	claims := CustomClaimsFromContext[*testCustomClaims](ctx)
	require.NotNil(t, claims)
	assert.Equal(t, "editor", claims.Role)
}

// TestCustomClaimsFromContext_WrongType returns zero when the custom claims are a different type.
func TestCustomClaimsFromContext_WrongType(t *testing.T) {
	type otherClaims struct{ Foo string }
	ctx := middlewareContext("eve", &testCustomClaims{Role: "admin"})
	claims := CustomClaimsFromContext[*otherClaims](ctx)
	assert.Nil(t, claims)
}

// TestCustomClaimsFromContext_DirectStoreFallback verifies fallback for unit tests
// that store claims directly (not wrapped in ValidatedClaims).
func TestCustomClaimsFromContext_DirectStoreFallback(t *testing.T) {
	direct := &testCustomClaims{Role: "viewer"}
	ctx := core.SetClaims(context.Background(), direct)
	claims := CustomClaimsFromContext[*testCustomClaims](ctx)
	require.NotNil(t, claims)
	assert.Equal(t, "viewer", claims.Role)
}

// TestCustomClaimsFromContext_Empty returns zero when no claims are set.
func TestCustomClaimsFromContext_Empty(t *testing.T) {
	assert.Nil(t, CustomClaimsFromContext[*testCustomClaims](context.Background()))
}

package auth

import (
	"context"
	"errors"
	"testing"

	jwtcore "github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authcontext "github.com/dioad/auth/authctx"
	"github.com/dioad/auth/oidc"
)

// TestDefaultPrincipalExtractor_FallbackChain tests that sources are tried in order
// and the first successful extraction is returned
func TestDefaultPrincipalExtractor_FallbackChain(t *testing.T) {
	tests := []struct {
		name            string
		sources         []PrincipalSource
		wantPrincipal   string
		wantSource      string
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "first source succeeds",
			sources: []PrincipalSource{
				&MockPrincipalSource{MockName: "source1", MockPrincipal: "user1"},
				&MockPrincipalSource{MockName: "source2", MockPrincipal: "user2"},
				&MockPrincipalSource{MockName: "source3", MockPrincipal: "user3"},
			},
			wantPrincipal: "user1",
			wantSource:    "source1",
			wantErr:       false,
		},
		{
			name: "first source returns empty, second succeeds",
			sources: []PrincipalSource{
				&MockPrincipalSource{MockName: "source1", MockPrincipal: ""},
				&MockPrincipalSource{MockName: "source2", MockPrincipal: "user2"},
				&MockPrincipalSource{MockName: "source3", MockPrincipal: "user3"},
			},
			wantPrincipal: "user2",
			wantSource:    "source2",
			wantErr:       false,
		},
		{
			name: "first source errors, second succeeds",
			sources: []PrincipalSource{
				&MockPrincipalSource{MockName: "source1", MockError: errors.New("source1 error")},
				&MockPrincipalSource{MockName: "source2", MockPrincipal: "user2"},
				&MockPrincipalSource{MockName: "source3", MockPrincipal: "user3"},
			},
			wantPrincipal: "user2",
			wantSource:    "source2",
			wantErr:       false,
		},
		{
			name: "all sources return empty - error with source list",
			sources: []PrincipalSource{
				&MockPrincipalSource{MockName: "source1", MockPrincipal: ""},
				&MockPrincipalSource{MockName: "source2", MockPrincipal: ""},
				&MockPrincipalSource{MockName: "source3", MockPrincipal: ""},
			},
			wantPrincipal:   "",
			wantErr:         true,
			wantErrContains: "source1",
		},
		{
			name: "all sources error - error with source list",
			sources: []PrincipalSource{
				&MockPrincipalSource{MockName: "source1", MockError: errors.New("error1")},
				&MockPrincipalSource{MockName: "source2", MockError: errors.New("error2")},
				&MockPrincipalSource{MockName: "source3", MockError: errors.New("error3")},
			},
			wantPrincipal:   "",
			wantErr:         true,
			wantErrContains: "source1",
		},
		{
			name: "third source succeeds after two failures",
			sources: []PrincipalSource{
				&MockPrincipalSource{MockName: "source1", MockPrincipal: ""},
				&MockPrincipalSource{MockName: "source2", MockError: errors.New("error2")},
				&MockPrincipalSource{MockName: "source3", MockPrincipal: "user3"},
			},
			wantPrincipal: "user3",
			wantSource:    "source3",
			wantErr:       false,
		},
		{
			name: "error message contains all source names",
			sources: []PrincipalSource{
				&MockPrincipalSource{MockName: "jwt", MockPrincipal: ""},
				&MockPrincipalSource{MockName: "oidc", MockPrincipal: ""},
				&MockPrincipalSource{MockName: "github", MockPrincipal: ""},
			},
			wantPrincipal:   "",
			wantErr:         true,
			wantErrContains: "[jwt oidc github]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := &defaultPrincipalExtractor{
				sources: tt.sources,
			}

			ctx := context.Background()

			principalCtx, err := extractor.ExtractPrincipal(ctx)

			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrContains != "" {
					assert.Contains(t, err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(t, err)

			require.NotNil(t, principalCtx)
			assert.Equal(t, tt.wantPrincipal, principalCtx.ID)
			assert.Equal(t, tt.wantSource, principalCtx.Source)
		})
	}
}

// TestDefaultPrincipalExtractor_Claims tests that claims are captured correctly
func TestDefaultPrincipalExtractor_Claims(t *testing.T) {
	testClaims := map[string]any{
		"email": "user@example.com",
		"role":  "admin",
	}

	extractor := &defaultPrincipalExtractor{
		sources: []PrincipalSource{
			&MockPrincipalSource{
				MockName:      "test-source",
				MockPrincipal: "testuser",
				MockClaims:    testClaims,
			},
		},
	}

	ctx := context.Background()

	principalCtx, err := extractor.ExtractPrincipal(ctx)

	require.NoError(t, err)
	assert.Equal(t, "testuser", principalCtx.ID)
	require.NotNil(t, principalCtx.Attributes, "ExtractPrincipal() claims is nil")
	assert.Equal(t, "user@example.com", principalCtx.Attributes["email"])
	assert.Equal(t, "admin", principalCtx.Attributes["role"])
}

// TestDefaultPrincipalExtractor_SourcePriority tests that sources are tried in the exact order provided
func TestDefaultPrincipalExtractor_SourcePriority(t *testing.T) {
	// All sources return a principal, but we should get the first one
	extractor := &defaultPrincipalExtractor{
		sources: []PrincipalSource{
			&MockPrincipalSource{MockName: "high-priority", MockPrincipal: "user-high"},
			&MockPrincipalSource{MockName: "medium-priority", MockPrincipal: "user-medium"},
			&MockPrincipalSource{MockName: "low-priority", MockPrincipal: "user-low"},
		},
	}

	ctx := context.Background()

	principalCtx, err := extractor.ExtractPrincipal(ctx)

	require.NoError(t, err)
	assert.Equal(t, "user-high", principalCtx.ID, "expected principal from highest priority source")
	assert.Equal(t, "high-priority", principalCtx.Source)
}

type testValidatedCustomClaims struct {
	Email       string         `json:"email,omitempty"`
	RealmAccess map[string]any `json:"realm_access,omitempty"`
}

func (c *testValidatedCustomClaims) Validate(_ context.Context) error { return nil }

// TestOIDCPrincipalSource_NilClaims tests that Extract doesn't panic when claims are nil
// This is a regression test for a bug where claims.Subject was accessed without nil check
func TestOIDCPrincipalSource_NilClaims(t *testing.T) {
	source := &oidcPrincipalSource{}

	// Context without any OIDC claims (claims will be nil)
	ctx := context.Background()

	principal, err := source.Extract(ctx)

	assert.NoError(t, err)

	// Should return empty string when claims are nil, not panic
	assert.Empty(t, principal)
}

// TestOIDCPrincipalSource_WithValidClaims tests that Extract works with valid claims
func TestOIDCPrincipalSource_WithValidClaims(t *testing.T) {
	source := &oidcPrincipalSource{}

	tests := []struct {
		name      string
		claims    *oidc.IntrospectionResponse
		wantPrinc string
	}{
		{
			name: "Subject used as fallback",
			claims: &oidc.IntrospectionResponse{
				Subject: "subject123",
			},
			wantPrinc: "subject123",
		},
		{
			name:      "Empty claims returns empty string",
			claims:    &oidc.IntrospectionResponse{},
			wantPrinc: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Put claims into context using the same mechanism as the JWT middleware
			ctx := jwtcore.SetClaims(context.Background(), tt.claims)

			principal, err := source.Extract(ctx)

			assert.NoError(t, err)
			assert.Equal(t, tt.wantPrinc, principal)
		})
	}
}

func TestOIDCPrincipalSource_RolesIncludesMappedClaims(t *testing.T) {
	source := &oidcPrincipalSource{
		RoleMapper: NewClaimRoleMapper([]ClaimRoleMapping{
			{
				Claims: map[string]string{"email": "smoke@example.com"},
				Role:   "registry.admin.readonly",
			},
		}),
	}

	claims := &oidc.IntrospectionResponse{
		Subject: "smoke-user",
		Email:   "smoke@example.com",
	}
	claims.RealmAccess.Roles = []string{"connect-admin"}
	ctx := jwtcore.SetClaims(context.Background(), claims)

	roles := source.Roles(ctx)

	require.Len(t, roles, 2, "roles: %v", roles)
	assert.Contains(t, roles, "connect-admin", "missing realm role")
	assert.Contains(t, roles, "registry.admin.readonly", "missing mapped role")
}

func TestOIDCPrincipalSource_RolesDedupe(t *testing.T) {
	source := &oidcPrincipalSource{
		RoleMapper: NewClaimRoleMapper([]ClaimRoleMapping{
			{
				Claims: map[string]string{"email": "smoke@example.com"},
				Role:   "registry.admin.readonly",
			},
		}),
	}

	claims := &oidc.IntrospectionResponse{
		Subject: "smoke-user",
		Email:   "smoke@example.com",
	}
	claims.RealmAccess.Roles = []string{"registry.admin.readonly"}
	ctx := jwtcore.SetClaims(context.Background(), claims)

	roles := source.Roles(ctx)
	require.Equal(t, []string{"registry.admin.readonly"}, roles)
}

func TestOIDCPrincipalSource_GroupsIncludedInRoles(t *testing.T) {
	source := &oidcPrincipalSource{}

	claims := &oidc.IntrospectionResponse{
		Subject: "smoke-user",
	}
	claims.RealmAccess.Roles = []string{"realm-role"}
	claims.Groups = []string{"connect-users", "admin-users"}
	ctx := jwtcore.SetClaims(context.Background(), claims)

	roles := source.Roles(ctx)

	assert.Contains(t, roles, "realm-role", "missing realm role")
	assert.Contains(t, roles, "connect-users", "missing OIDC group connect-users")
	assert.Contains(t, roles, "admin-users", "missing OIDC group admin-users")
}

func TestOIDCPrincipalSource_GroupsDeduped(t *testing.T) {
	source := &oidcPrincipalSource{}

	claims := &oidc.IntrospectionResponse{Subject: "smoke-user"}
	claims.RealmAccess.Roles = []string{"connect-users"} // same as group
	claims.Groups = []string{"connect-users"}
	ctx := jwtcore.SetClaims(context.Background(), claims)

	roles := source.Roles(ctx)

	count := 0
	for _, r := range roles {
		if r == "connect-users" {
			count++
		}
	}
	assert.Equal(t, 1, count, "Roles() should deduplicate connect-users; got %v", roles)
}

func TestDefaultPrincipalExtractor_JWTSourcePreferredForNonOIDCValidatedClaims(t *testing.T) {
	extractor := NewDefaultPrincipalExtractor()

	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "jwt-subject",
			Issuer:  "issuer.example",
		},
		CustomClaims: &testValidatedCustomClaims{
			Email: "jwt@example.com",
			RealmAccess: map[string]any{
				"roles": []any{"connect-admin"},
			},
		},
	}

	ctx := jwtcore.SetClaims(context.Background(), vc)
	ctx = authcontext.ContextWithAuthenticatedPrincipal(ctx, "jwt-subject")

	principalCtx, err := extractor.ExtractPrincipal(ctx)
	require.NoError(t, err)

	require.Equal(t, "jwt", principalCtx.Source)
	require.Equal(t, "jwt-subject", principalCtx.ID)
}

func TestDefaultPrincipalExtractor_UsesJWTMapperForGenericValidatedClaims(t *testing.T) {
	extractor := NewDefaultPrincipalExtractorWithConfig(DefaultExtractorConfig{
		OIDCMapper: NewClaimRoleMapper([]ClaimRoleMapping{
			{
				Claims: map[string]string{"email": "jwt@example.com"},
				Role:   "oidc-role",
			},
		}),
		JWTMapper: NewClaimRoleMapper([]ClaimRoleMapping{
			{
				Claims: map[string]string{"email": "jwt@example.com"},
				Role:   "jwt-role",
			},
		}),
	})

	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "jwt-subject",
		},
		CustomClaims: &testValidatedCustomClaims{
			Email: "jwt@example.com",
		},
	}

	ctx := jwtcore.SetClaims(context.Background(), vc)
	ctx = authcontext.ContextWithAuthenticatedPrincipal(ctx, "jwt-subject")

	principalCtx, err := extractor.ExtractPrincipal(ctx)
	require.NoError(t, err)

	require.Equal(t, "jwt", principalCtx.Source)
	assert.Contains(t, principalCtx.Roles, "jwt-role")
	assert.NotContains(t, principalCtx.Roles, "oidc-role")
}

func TestJWTPrincipalSource_RolesIncludeMappedCustomClaims(t *testing.T) {
	source := &jwtPrincipalSource{
		RoleMapper: NewClaimRoleMapper([]ClaimRoleMapping{
			{
				Claims: map[string]string{"email": "smoke@example.com"},
				Role:   "registry.admin.readonly",
			},
		}),
	}

	ctx := context.Background()
	ctx = authcontext.ContextWithAuthenticatedPrincipal(ctx, "smoke-principal")
	ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, map[string]any{
		"email": "smoke@example.com",
	})

	roles := source.Roles(ctx)
	assert.Contains(t, roles, "registry.admin.readonly", "expected mapped role")
}

func TestJWTPrincipalSource_ClaimsPreserveAuthenticatedPrincipal(t *testing.T) {
	source := &jwtPrincipalSource{
		RoleMapper: NewClaimRoleMapper([]ClaimRoleMapping{
			{
				Claims: map[string]string{"principal": "smoke-principal"},
				Role:   "registry.admin.readonly",
			},
		}),
	}

	ctx := context.Background()
	ctx = authcontext.ContextWithAuthenticatedPrincipal(ctx, "smoke-principal")
	ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, map[string]any{
		"principal": "token-controlled",
	})

	claims := source.Claims(ctx)
	require.Equal(t, "smoke-principal", claims["principal"])

	roles := source.Roles(ctx)
	assert.Contains(t, roles, "registry.admin.readonly", "expected mapped role from authenticated principal")
}

func TestJWTPrincipalSource_RolesIncludeNativeClaimsRoles(t *testing.T) {
	source := &jwtPrincipalSource{}

	ctx := context.Background()
	ctx = authcontext.ContextWithAuthenticatedPrincipal(ctx, "smoke-principal")
	ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"registry.admin.readonly"},
		},
	})

	roles := source.Roles(ctx)
	assert.Contains(t, roles, "registry.admin.readonly", "expected native realm_access role")
}

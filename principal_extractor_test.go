package auth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	jwtcore "github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"

	authcontext "github.com/dioad/auth/http/context"
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
			req := &http.Request{}
			req = req.WithContext(ctx)

			principalCtx, err := extractor.ExtractPrincipal(ctx, req)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractPrincipal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Error("ExtractPrincipal() expected error but got nil")
				} else if tt.wantErrContains != "" {
					errMsg := err.Error()
					if !contains(errMsg, tt.wantErrContains) {
						t.Errorf("ExtractPrincipal() error = %v, want error containing %v", err, tt.wantErrContains)
					}
				}
				return
			}

			if principalCtx.ID != tt.wantPrincipal {
				t.Errorf("ExtractPrincipal() principal = %v, want %v", principalCtx.ID, tt.wantPrincipal)
			}

			if principalCtx == nil {
				t.Error("ExtractPrincipal() principalCtx is nil")
				return
			}

			if principalCtx.Source != tt.wantSource {
				t.Errorf("ExtractPrincipal() source = %v, want %v", principalCtx.Source, tt.wantSource)
			}
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
	req := &http.Request{}
	req = req.WithContext(ctx)

	principalCtx, err := extractor.ExtractPrincipal(ctx, req)

	if err != nil {
		t.Fatalf("ExtractPrincipal() unexpected error: %v", err)
	}

	if principalCtx.ID != "testuser" {
		t.Errorf("ExtractPrincipal() principal = %v, want testuser", principalCtx.ID)
	}

	if principalCtx.Attributes == nil {
		t.Fatal("ExtractPrincipal() claims is nil")
	}

	if principalCtx.Attributes["email"] != "user@example.com" {
		t.Errorf("ExtractPrincipal() claims[email] = %v, want user@example.com", principalCtx.Attributes["email"])
	}

	if principalCtx.Attributes["role"] != "admin" {
		t.Errorf("ExtractPrincipal() claims[role] = %v, want admin", principalCtx.Attributes["role"])
	}
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
	req := &http.Request{}
	req = req.WithContext(ctx)

	principalCtx, err := extractor.ExtractPrincipal(ctx, req)

	if err != nil {
		t.Fatalf("ExtractPrincipal() unexpected error: %v", err)
	}

	if principalCtx.ID != "user-high" {
		t.Errorf("ExtractPrincipal() principal = %v, want user-high (from highest priority source)", principalCtx.ID)
	}

	if principalCtx.Source != "high-priority" {
		t.Errorf("ExtractPrincipal() source = %v, want high-priority", principalCtx.Source)
	}
}

// contains is a helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestOIDCPrincipalSource_NilClaims tests that Extract doesn't panic when claims are nil
// This is a regression test for a bug where claims.Subject was accessed without nil check
func TestOIDCPrincipalSource_NilClaims(t *testing.T) {
	source := &oidcPrincipalSource{}

	// Context without any OIDC claims (claims will be nil)
	ctx := context.Background()

	principal, err := source.Extract(ctx, nil)

	if err != nil {
		t.Errorf("Extract() unexpected error: %v", err)
	}

	// Should return empty string when claims are nil, not panic
	if principal != "" {
		t.Errorf("Extract() principal = %v, want empty string", principal)
	}
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

			principal, err := source.Extract(ctx, nil)

			if err != nil {
				t.Errorf("Extract() unexpected error: %v", err)
			}

			if principal != tt.wantPrinc {
				t.Errorf("Extract() principal = %v, want %v", principal, tt.wantPrinc)
			}
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

	if len(roles) != 2 {
		t.Fatalf("Roles() len = %d, want 2 (%v)", len(roles), roles)
	}
	if !sliceContains(roles, "connect-admin") {
		t.Fatalf("Roles() missing realm role connect-admin: %v", roles)
	}
	if !sliceContains(roles, "registry.admin.readonly") {
		t.Fatalf("Roles() missing mapped role registry.admin.readonly: %v", roles)
	}
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
	if len(roles) != 1 || roles[0] != "registry.admin.readonly" {
		t.Fatalf("Roles() = %v, want [registry.admin.readonly]", roles)
	}
}

func TestDefaultPrincipalExtractor_JWTSourcePreferredForNonOIDCValidatedClaims(t *testing.T) {
	extractor := NewDefaultPrincipalExtractor()

	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "jwt-subject",
			Issuer:  "issuer.example",
		},
	}

	ctx := jwtcore.SetClaims(context.Background(), vc)
	ctx = authcontext.ContextWithAuthenticatedPrincipal(ctx, "jwt-subject")
	req := (&http.Request{}).WithContext(ctx)

	principalCtx, err := extractor.ExtractPrincipal(ctx, req)
	if err != nil {
		t.Fatalf("ExtractPrincipal() unexpected error: %v", err)
	}

	if principalCtx.Source != "jwt" {
		t.Fatalf("ExtractPrincipal() source = %q, want %q", principalCtx.Source, "jwt")
	}
	if principalCtx.ID != "jwt-subject" {
		t.Fatalf("ExtractPrincipal() ID = %q, want %q", principalCtx.ID, "jwt-subject")
	}
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
	if !sliceContains(roles, "registry.admin.readonly") {
		t.Fatalf("Roles() = %v, expected mapped role", roles)
	}
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
	if !sliceContains(roles, "registry.admin.readonly") {
		t.Fatalf("Roles() = %v, expected native realm_access role", roles)
	}
}

func sliceContains(values []string, target string) bool {
	return slices.Contains(values, target)
}

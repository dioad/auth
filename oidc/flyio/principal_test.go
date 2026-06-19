package flyio

import (
	"context"
	"testing"

	"github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authcontext "github.com/dioad/auth/authctx"
)

// TestExtract_WithFlyioClaims verifies that Extract returns the subject from Fly.io claims.
func TestExtract_WithFlyioClaims(t *testing.T) {
	claims := &Claims{
		CustomClaims: CustomClaims{
			AppName:   "my-app",
			OrgName:   "my-org",
			MachineId: "machine-123",
		},
	}

	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "my-machine-id",
		},
		CustomClaims: claims,
	}
	ctx := core.SetClaims(context.Background(), vc)

	s := &PrincipalSource{}
	principal, err := s.Extract(ctx)

	require.NoError(t, err)
	assert.Equal(t, "my-machine-id", principal)
}

// TestExtract_WithoutFlyioClaims verifies that Extract returns empty string and nil error
// when Fly.io claims are absent. This is the "not applicable" case for the fallback chain.
func TestExtract_WithoutFlyioClaims(t *testing.T) {
	// Store a different claim type (e.g., generic OIDC token)
	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "some-user",
		},
		CustomClaims: nil, // No Fly.io claims
	}
	ctx := core.SetClaims(context.Background(), vc)

	s := &PrincipalSource{}
	principal, err := s.Extract(ctx)

	require.NoError(t, err)
	assert.Equal(t, "", principal)
}

// TestExtract_EmptyContext verifies that Extract returns empty string and nil error
// when no claims are in context at all.
func TestExtract_EmptyContext(t *testing.T) {
	s := &PrincipalSource{}
	principal, err := s.Extract(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "", principal)
}

// TestName verifies that Name returns the provider identifier.
func TestName(t *testing.T) {
	s := &PrincipalSource{}
	assert.Equal(t, "flyio", s.Name())
}

// TestIsService verifies that IsService returns true only when Fly.io claims are present.
func TestIsService(t *testing.T) {
	tests := []struct {
		name     string
		claims   jwtvalidator.CustomClaims
		wantTrue bool
	}{
		{
			name: "with flyio claims",
			claims: &Claims{
				CustomClaims: CustomClaims{MachineId: "machine-123"},
			},
			wantTrue: true,
		},
		{
			name:     "without flyio claims",
			claims:   nil,
			wantTrue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vc := &jwtvalidator.ValidatedClaims{
				CustomClaims: tt.claims,
			}
			ctx := core.SetClaims(context.Background(), vc)

			s := &PrincipalSource{}
			assert.Equal(t, tt.wantTrue, s.IsService(ctx))
		})
	}
}

// TestClaims verifies that Claims returns a map with both canonical and provider-specific keys.
func TestClaims(t *testing.T) {
	claims := &Claims{
		CustomClaims: CustomClaims{
			AppId:          "app-123",
			AppName:        "my-app",
			OrgId:          "org-456",
			OrgName:        "my-org",
			MachineId:      "machine-789",
			MachineName:    "prod-vm-1",
			MachineVersion: "v1.0",
			Image:          "image-digest-123",
			ImageDigest:    "sha256:abcdef",
			Region:         "us-east-1",
		},
	}

	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "my-machine-id",
		},
		CustomClaims: claims,
	}
	ctx := core.SetClaims(context.Background(), vc)

	s := &PrincipalSource{}
	claimsMap := s.Claims(ctx)

	// Verify canonical key
	assert.Equal(t, "my-machine-id", claimsMap["username"])

	// Verify provider-specific keys
	assert.Equal(t, "app-123", claimsMap["app_id"])
	assert.Equal(t, "my-app", claimsMap["app_name"])
	assert.Equal(t, "org-456", claimsMap["org_id"])
	assert.Equal(t, "my-org", claimsMap["org_name"])
	assert.Equal(t, "machine-789", claimsMap["machine_id"])
	assert.Equal(t, "prod-vm-1", claimsMap["machine_name"])
	assert.Equal(t, "v1.0", claimsMap["machine_version"])
	assert.Equal(t, "image-digest-123", claimsMap["image"])
	assert.Equal(t, "sha256:abcdef", claimsMap["image_digest"])
	assert.Equal(t, "us-east-1", claimsMap["region"])
}

// TestClaims_EmptyContext verifies that Claims returns an empty map when no claims are present.
func TestClaims_EmptyContext(t *testing.T) {
	s := &PrincipalSource{}
	claimsMap := s.Claims(context.Background())

	assert.NotNil(t, claimsMap)
	assert.Empty(t, claimsMap)
}

// TestHasValidClaims verifies the Fly.io fingerprint predicate.
func TestHasValidClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{
			name: "full machine claims",
			claims: map[string]any{
				"app_id":     "app-123",
				"machine_id": "machine-456",
			},
			want: true,
		},
		{
			name: "app_id with machine_name",
			claims: map[string]any{
				"app_id":       "app-123",
				"machine_name": "cold-shape-2007",
			},
			want: true,
		},
		{
			name: "app_id with image",
			claims: map[string]any{
				"app_id": "app-123",
				"image":  "registry.fly.io/my-app:latest",
			},
			want: true,
		},
		{
			name: "missing app_id",
			claims: map[string]any{
				"machine_id": "machine-456",
				"app_name":   "my-app",
			},
			want: false,
		},
		{
			name: "app_id but no machine indicators",
			claims: map[string]any{
				"app_id":   "app-123",
				"app_name": "my-app",
				"org_name": "my-org",
			},
			want: false,
		},
		{
			name:   "empty claims",
			claims: map[string]any{},
			want:   false,
		},
		{
			name:   "nil claims",
			claims: nil,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, HasValidClaims(tt.claims))
		})
	}
}

// TestExtract_WithGenericClaims verifies that Extract returns the principal from
// authcontext generic claims when they fingerprint as a Fly.io token.
func TestExtract_WithGenericClaims(t *testing.T) {
	claims := map[string]any{
		"app_id":     "app-123",
		"machine_id": "machine-456",
		"app_name":   "my-app",
	}
	ctx := authcontext.ContextWithAuthenticatedPrincipal(context.Background(), "my-org:my-app:cold-shape")
	ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, claims)

	s := &PrincipalSource{}
	principal, err := s.Extract(ctx)

	require.NoError(t, err)
	assert.Equal(t, "my-org:my-app:cold-shape", principal)
}

// TestExtract_WithGenericClaims_NoMatch verifies that Extract returns empty
// string when generic claims do not match the Fly.io fingerprint.
func TestExtract_WithGenericClaims_NoMatch(t *testing.T) {
	claims := map[string]any{
		"app_name": "my-app",
		"org_name": "my-org",
		// no app_id or machine_* keys
	}
	ctx := authcontext.ContextWithAuthenticatedPrincipal(context.Background(), "some-principal")
	ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, claims)

	s := &PrincipalSource{}
	principal, err := s.Extract(ctx)

	require.NoError(t, err)
	assert.Equal(t, "", principal)
}

// TestIsService_WithGenericClaims verifies IsService returns true for Fly.io
// generic claims and false for non-matching generic claims.
func TestIsService_WithGenericClaims(t *testing.T) {
	t.Run("matching generic claims", func(t *testing.T) {
		ctx := authcontext.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{
			"app_id":     "app-123",
			"machine_id": "machine-456",
		})
		s := &PrincipalSource{}
		assert.True(t, s.IsService(ctx))
	})

	t.Run("non-matching generic claims", func(t *testing.T) {
		ctx := authcontext.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{
			"app_name": "my-app",
		})
		s := &PrincipalSource{}
		assert.False(t, s.IsService(ctx))
	})
}

// TestClaims_WithGenericClaims verifies that Claims returns provider keys from
// generic context claims when they fingerprint as a Fly.io token.
func TestClaims_WithGenericClaims(t *testing.T) {
	claims := map[string]any{
		"app_id":          "app-123",
		"app_name":        "my-app",
		"machine_id":      "machine-456",
		"machine_name":    "cold-shape-2007",
		"org_name":        "my-org",
		"org_id":          "org-789",
		"machine_version": "v1",
		"region":          "lhr",
	}
	ctx := authcontext.ContextWithAuthenticatedPrincipal(context.Background(), "my-org:my-app:cold-shape")
	ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, claims)

	s := &PrincipalSource{}
	result := s.Claims(ctx)

	assert.Equal(t, "my-org:my-app:cold-shape", result["username"])
	assert.Equal(t, "app-123", result["app_id"])
	assert.Equal(t, "my-app", result["app_name"])
	assert.Equal(t, "machine-456", result["machine_id"])
	assert.Equal(t, "cold-shape-2007", result["machine_name"])
	assert.Equal(t, "my-org", result["org_name"])
}

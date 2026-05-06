package flyio

import (
	"context"
	"testing"

	"github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtract_WithFlyioClaims verifies that Extract returns the subject from Fly.io claims.
func TestExtract_WithFlyioClaims(t *testing.T) {
	claims := &Claims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "my-machine-id",
		},
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
	principal, err := s.Extract(ctx, nil)

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
	principal, err := s.Extract(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, "", principal)
}

// TestExtract_EmptyContext verifies that Extract returns empty string and nil error
// when no claims are in context at all.
func TestExtract_EmptyContext(t *testing.T) {
	s := &PrincipalSource{}
	principal, err := s.Extract(context.Background(), nil)

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
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "my-machine-id",
		},
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

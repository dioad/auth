package githubactions

import (
	"context"
	"testing"

	"github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtract_WithGitHubActionsClaims verifies that Extract returns the subject from GitHub Actions claims.
func TestExtract_WithGitHubActionsClaims(t *testing.T) {
	claims := &Claims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "repo:octocat/Hello-World:ref:refs/heads/main",
		},
		CustomClaims: CustomClaims{
			Actor:      "octocat",
			Repository: "octocat/Hello-World",
			Workflow:   "build",
		},
	}

	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "repo:octocat/Hello-World:ref:refs/heads/main",
		},
		CustomClaims: claims,
	}
	ctx := core.SetClaims(context.Background(), vc)

	s := &PrincipalSource{}
	principal, err := s.Extract(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, "repo:octocat/Hello-World:ref:refs/heads/main", principal)
}

// TestExtract_WithoutGitHubActionsClaims verifies that Extract returns empty string and nil error
// when GitHub Actions claims are absent. This is the "not applicable" case for the fallback chain.
func TestExtract_WithoutGitHubActionsClaims(t *testing.T) {
	// Store a different claim type (e.g., generic OIDC token)
	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "some-user",
		},
		CustomClaims: nil, // No GitHub Actions claims
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
	assert.Equal(t, "githubactions", s.Name())
}

// TestIsService verifies that IsService returns true only when GitHub Actions claims are present.
func TestIsService(t *testing.T) {
	tests := []struct {
		name     string
		claims   jwtvalidator.CustomClaims
		wantTrue bool
	}{
		{
			name: "with github actions claims",
			claims: &Claims{
				CustomClaims: CustomClaims{Actor: "octocat"},
			},
			wantTrue: true,
		},
		{
			name:     "without github actions claims",
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

// TestClaims verifies that Claims returns a map with provider-specific keys.
func TestClaims(t *testing.T) {
	claims := &Claims{
		CustomClaims: CustomClaims{
			Actor:             "octocat",
			ActorID:           "1",
			Repository:        "octocat/Hello-World",
			RepositoryID:      "12345",
			RepositoryOwner:   "octocat",
			RepositoryOwnerID: "1",
			Environment:       "production",
			EventName:         "push",
			Ref:               "refs/heads/main",
			RefType:           "branch",
			SHA:               "abc123def456",
			Workflow:          "build",
			WorkflowRef:       "octocat/Hello-World/.github/workflows/build.yml@main",
			WorkflowSHA:       "workflow-sha-123",
			JobWorkflowRef:    "octocat/Hello-World/.github/workflows/build.yml@main",
			RunID:             "12345",
			RunNumber:         "1",
			RunAttempt:        "1",
			RunnerEnvironment: "github-hosted",
		},
	}

	vc := &jwtvalidator.ValidatedClaims{
		CustomClaims: claims,
	}
	ctx := core.SetClaims(context.Background(), vc)

	s := &PrincipalSource{}
	claimsMap := s.Claims(ctx)

	// Verify canonical key
	assert.Equal(t, "octocat", claimsMap["username"])

	// Verify provider-specific keys
	assert.Equal(t, "octocat/Hello-World", claimsMap["repository"])
	assert.Equal(t, "octocat", claimsMap["repository_owner"])
	assert.Equal(t, "production", claimsMap["environment"])
	assert.Equal(t, "push", claimsMap["event_name"])
	assert.Equal(t, "refs/heads/main", claimsMap["ref"])
	assert.Equal(t, "branch", claimsMap["ref_type"])
	assert.Equal(t, "abc123def456", claimsMap["sha"])
	assert.Equal(t, "build", claimsMap["workflow"])
	assert.Equal(t, "octocat/Hello-World/.github/workflows/build.yml@main", claimsMap["workflow_ref"])
	assert.Equal(t, "octocat/Hello-World/.github/workflows/build.yml@main", claimsMap["job_workflow_ref"])
	assert.Equal(t, "12345", claimsMap["run_id"])
	assert.Equal(t, "1", claimsMap["run_number"])
	assert.Equal(t, "1", claimsMap["run_attempt"])
	assert.Equal(t, "github-hosted", claimsMap["runner_environment"])
}

// TestClaims_EmptyContext verifies that Claims returns an empty map when no claims are present.
func TestClaims_EmptyContext(t *testing.T) {
	s := &PrincipalSource{}
	claimsMap := s.Claims(context.Background())

	assert.NotNil(t, claimsMap)
	assert.Empty(t, claimsMap)
}

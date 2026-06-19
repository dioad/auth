package githubactions

import (
	"context"
	"testing"

	"github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authcontext "github.com/dioad/auth/authctx"
)

// TestExtract_WithGitHubActionsClaims verifies that Extract returns the subject from GitHub Actions claims.
func TestExtract_WithGitHubActionsClaims(t *testing.T) {
	claims := &Claims{
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

// TestHHasValidClaims verifies the GitHub Actions fingerprint predicate.
func TestHHasValidClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{
			name: "repository with job_workflow_ref",
			claims: map[string]any{
				"repository":       "myorg/infra",
				"job_workflow_ref": "myorg/infra/.github/workflows/deploy.yaml@refs/heads/main",
			},
			want: true,
		},
		{
			name: "repository with run_id",
			claims: map[string]any{
				"repository": "myorg/infra",
				"run_id":     "12345",
			},
			want: true,
		},
		{
			name: "repository with runner_environment",
			claims: map[string]any{
				"repository":         "myorg/infra",
				"runner_environment": "github-hosted",
			},
			want: true,
		},
		{
			name: "missing repository",
			claims: map[string]any{
				"job_workflow_ref": "myorg/infra/.github/workflows/deploy.yaml@refs/heads/main",
				"run_id":           "12345",
			},
			want: false,
		},
		{
			name: "repository but no workflow/run indicators",
			claims: map[string]any{
				"repository": "myorg/infra",
				"ref":        "refs/heads/main",
			},
			want: false,
		},
		{
			name:   "empty claims",
			claims: map[string]any{},
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
// authcontext generic claims when they fingerprint as a GitHub Actions token.
func TestExtract_WithGenericClaims(t *testing.T) {
	claims := map[string]any{
		"repository":       "myorg/infra",
		"job_workflow_ref": "myorg/infra/.github/workflows/deploy.yaml@refs/heads/main",
		"run_id":           "12345",
	}
	ctx := authcontext.ContextWithAuthenticatedPrincipal(context.Background(), "repo:myorg/infra:run:12345")
	ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, claims)

	s := &PrincipalSource{}
	principal, err := s.Extract(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, "repo:myorg/infra:run:12345", principal)
}

// TestExtract_WithGenericClaims_NoMatch verifies that Extract returns empty
// string when generic claims do not fingerprint as GitHub Actions.
func TestExtract_WithGenericClaims_NoMatch(t *testing.T) {
	claims := map[string]any{
		"repository": "myorg/infra",
		"ref":        "refs/heads/main",
		// no workflow/run indicators
	}
	ctx := authcontext.ContextWithAuthenticatedPrincipal(context.Background(), "some-principal")
	ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, claims)

	s := &PrincipalSource{}
	principal, err := s.Extract(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, "", principal)
}

// TestIsService_WithGenericClaims verifies IsService returns true for GitHub
// Actions generic claims and false for non-matching generic claims.
func TestIsService_WithGenericClaims(t *testing.T) {
	t.Run("matching generic claims", func(t *testing.T) {
		ctx := authcontext.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{
			"repository":       "myorg/infra",
			"job_workflow_ref": "myorg/infra/.github/workflows/deploy.yaml@refs/heads/main",
		})
		s := &PrincipalSource{}
		assert.True(t, s.IsService(ctx))
	})

	t.Run("non-matching generic claims", func(t *testing.T) {
		ctx := authcontext.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{
			"repository": "myorg/infra",
			"ref":        "refs/heads/main",
		})
		s := &PrincipalSource{}
		assert.False(t, s.IsService(ctx))
	})
}

// TestClaims_WithGenericClaims verifies that Claims returns provider keys from
// generic context claims when they fingerprint as a GitHub Actions token.
func TestClaims_WithGenericClaims(t *testing.T) {
	claims := map[string]any{
		"repository":       "myorg/infra",
		"job_workflow_ref": "myorg/infra/.github/workflows/deploy.yaml@refs/heads/main",
		"run_id":           "12345",
		"actor":            "octocat",
	}
	ctx := authcontext.ContextWithAuthenticatedPrincipal(context.Background(), "repo:myorg/infra:run:12345")
	ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, claims)

	s := &PrincipalSource{}
	result := s.Claims(ctx)

	assert.Equal(t, "octocat", result["username"])
	assert.Equal(t, "myorg/infra", result["repository"])
	assert.Equal(t, "myorg/infra/.github/workflows/deploy.yaml@refs/heads/main", result["job_workflow_ref"])
	assert.Equal(t, "12345", result["run_id"])
}

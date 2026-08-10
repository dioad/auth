package githubactions

import (
	"context"
	"maps"

	"github.com/dioad/auth/authctx"
	"github.com/dioad/auth/mapper"
	"github.com/dioad/auth/oidc/oidcutil"
)

// HasValidClaims reports whether claims contains enough GitHub Actions-specific
// fields to be treated as a GitHub Actions OIDC token. It requires the
// repository claim plus at least one workflow/run indicator to reduce false
// positives for repositories that happen to include ref-only claims.
func HasValidClaims(claims map[string]any) bool {
	if !oidcutil.HasNonEmptyString(claims, "repository") {
		return false
	}
	return oidcutil.HasAnyNonEmptyString(claims,
		"job_workflow_ref",
		"workflow_ref",
		"run_id",
		"run_number",
		"runner_environment",
		"workflow_sha",
	)
}

// ClaimsMap implements oidcutil.ClaimsMapper, flattening the typed GitHub
// Actions claims. "username" is seeded from the claims' own Actor field, so
// subject (the token's registered "sub" claim) is unused.
func (c *Claims) ClaimsMap(_ string) map[string]any {
	result := make(map[string]any, 20)
	if c.Actor != "" {
		result["username"] = c.Actor
	}
	result["actor"] = c.Actor
	result["actor_id"] = c.ActorID
	result["base_ref"] = c.BaseRef
	result["environment"] = c.Environment
	result["event_name"] = c.EventName
	result["head_ref"] = c.HeadRef
	result["job_workflow_ref"] = c.JobWorkflowRef
	result["ref"] = c.Ref
	result["ref_type"] = c.RefType
	result["repository"] = c.Repository
	result["repository_id"] = c.RepositoryID
	result["repository_owner"] = c.RepositoryOwner
	result["repository_owner_id"] = c.RepositoryOwnerID
	result["run_attempt"] = c.RunAttempt
	result["run_id"] = c.RunID
	result["run_number"] = c.RunNumber
	result["runner_environment"] = c.RunnerEnvironment
	result["sha"] = c.SHA
	result["workflow"] = c.Workflow
	result["workflow_ref"] = c.WorkflowRef
	result["workflow_sha"] = c.WorkflowSHA
	return result
}

// PrincipalSource extracts principal identity from GitHub Actions OIDC tokens.
type PrincipalSource struct {
	// RoleMapper maps raw GitHub Actions JWT claims to internal role strings.
	// When nil, Roles returns nil.
	RoleMapper mapper.Mapper
}

// Roles returns the internal roles derived from GitHub Actions claims via the
// configured RoleMapper. Returns nil when no mapper is set.
func (s *PrincipalSource) Roles(ctx context.Context) []string {
	return oidcutil.GenericRoles(s.RoleMapper, s.Claims(ctx))
}

// Extract returns the principal subject from a GitHub Actions token. It first
// attempts the typed-claims path (JWT middleware configured with a GitHub
// Actions validator), then falls back to fingerprinting generic validated claims
// stored by a non-typed JWT middleware.
func (s *PrincipalSource) Extract(ctx context.Context) (string, error) {
	return oidcutil.GenericExtract[Claims](ctx, HasValidClaims)
}

func (s *PrincipalSource) Name() string {
	return "githubactions"
}

// Claims returns the GitHub Actions token claims as a map. Canonical attribute
// keys (e.g. "username") are included alongside raw GitHub Actions claim names
// so that ClaimRoleMapper rules can reference either form.
func (s *PrincipalSource) Claims(ctx context.Context) map[string]any {
	return oidcutil.GenericClaims[Claims](ctx, HasValidClaims, genericClaims)
}

// IsService returns true for any valid GitHub Actions token, as these represent
// automated workflow identities rather than human users.
func (s *PrincipalSource) IsService(ctx context.Context) bool {
	return oidcutil.GenericIsService[Claims](ctx, HasValidClaims)
}

// genericClaims builds the fallback-path Claims() result: the raw custom
// claims map, seeded with a canonical "username" key (preferring the "actor"
// claim, then the authenticated principal) when missing.
func genericClaims(ctx context.Context, custom map[string]any) map[string]any {
	result := make(map[string]any, len(custom)+1)
	maps.Copy(result, custom)
	if _, exists := result["username"]; !exists {
		if actor, ok := custom["actor"].(string); ok && actor != "" {
			result["username"] = actor
		} else if principal, ok := authctx.AuthenticatedPrincipalFromContext(ctx); ok && principal != "" {
			result["username"] = principal
		}
	}
	return result
}

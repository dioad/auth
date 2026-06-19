package githubactions

import (
	"context"
	"maps"
	"net/http"

	"github.com/dioad/auth/authctx"
	"github.com/dioad/auth/jwt"
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

// PrincipalSource extracts principal identity from GitHub Actions OIDC tokens.
type PrincipalSource struct {
	// RoleMapper maps raw GitHub Actions JWT claims to internal role strings.
	// When nil, Roles returns nil.
	RoleMapper mapper.Mapper
}

// Roles returns the internal roles derived from GitHub Actions claims via the
// configured RoleMapper. Returns nil when no mapper is set.
func (s *PrincipalSource) Roles(ctx context.Context) []string {
	if s.RoleMapper == nil {
		return nil
	}
	return s.RoleMapper.MapRoles(s.Claims(ctx))
}

// Extract returns the principal subject from a GitHub Actions token. It first
// attempts the typed-claims path (JWT middleware configured with a GitHub
// Actions validator), then falls back to fingerprinting generic validated claims
// stored by a non-typed JWT middleware.
func (s *PrincipalSource) Extract(ctx context.Context, _ *http.Request) (string, error) {
	// Typed path: JWT middleware configured with a GitHub Actions-specific validator.
	if claims := jwt.CustomClaimsFromContext[*Claims](ctx); claims != nil {
		registered := jwt.RegisteredClaimsFromContext(ctx)
		if registered == nil {
			return "", nil
		}
		return registered.Subject, nil
	}
	// Generic path: JWT middleware using a generic validator. Fingerprint the
	// custom claims map to confirm this is a GitHub Actions token before extracting.
	custom, ok := authctx.AuthenticatedCustomClaimsFromContext(ctx)
	if !ok || !HasValidClaims(custom) {
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

func (s *PrincipalSource) Name() string {
	return "githubactions"
}

// Claims returns the GitHub Actions token claims as a map. Canonical attribute
// keys (e.g. "username") are included alongside raw GitHub Actions claim names
// so that ClaimRoleMapper rules can reference either form.
func (s *PrincipalSource) Claims(ctx context.Context) map[string]any {
	result := make(map[string]any)

	// Typed path.
	if claims := jwt.CustomClaimsFromContext[*Claims](ctx); claims != nil {
		if claims.Actor != "" {
			result["username"] = claims.Actor
		}
		result["actor"] = claims.Actor
		result["actor_id"] = claims.ActorID
		result["base_ref"] = claims.BaseRef
		result["environment"] = claims.Environment
		result["event_name"] = claims.EventName
		result["head_ref"] = claims.HeadRef
		result["job_workflow_ref"] = claims.JobWorkflowRef
		result["ref"] = claims.Ref
		result["ref_type"] = claims.RefType
		result["repository"] = claims.Repository
		result["repository_id"] = claims.RepositoryID
		result["repository_owner"] = claims.RepositoryOwner
		result["repository_owner_id"] = claims.RepositoryOwnerID
		result["run_attempt"] = claims.RunAttempt
		result["run_id"] = claims.RunID
		result["run_number"] = claims.RunNumber
		result["runner_environment"] = claims.RunnerEnvironment
		result["sha"] = claims.SHA
		result["workflow"] = claims.Workflow
		result["workflow_ref"] = claims.WorkflowRef
		result["workflow_sha"] = claims.WorkflowSHA
		return result
	}

	// Generic path: include all claims from the context custom claims map.
	custom, ok := authctx.AuthenticatedCustomClaimsFromContext(ctx)
	if !ok || !HasValidClaims(custom) {
		return result
	}
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

// IsService returns true for any valid GitHub Actions token, as these represent
// automated workflow identities rather than human users.
func (s *PrincipalSource) IsService(ctx context.Context) bool {
	if jwt.CustomClaimsFromContext[*Claims](ctx) != nil {
		return true
	}
	custom, _ := authctx.AuthenticatedCustomClaimsFromContext(ctx)
	return HasValidClaims(custom)
}

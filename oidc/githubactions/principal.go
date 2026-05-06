package githubactions

import (
	"context"
	"net/http"

	"github.com/dioad/auth/jwt"
	"github.com/dioad/auth/mapper"
)

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

func (s *PrincipalSource) Extract(ctx context.Context, _ *http.Request) (string, error) {
	// Guard on GitHub Actions-specific custom claims so this source does not
	// claim tokens issued by other providers. Return ("", nil) for non-GitHub
	// Actions tokens to avoid noisy logs in the fallback chain; only return
	// error for actual extraction failures.
	claims := jwt.CustomClaimsFromContext[*Claims](ctx)
	if claims == nil {
		return "", nil
	}
	return claims.Subject, nil
}

func (s *PrincipalSource) Name() string {
	return "githubactions"
}

// Claims returns the GitHub Actions token claims as a map. Canonical attribute
// keys (e.g. "username") are included alongside raw GitHub Actions claim names
// so that ClaimRoleMapper rules can reference either form.
func (s *PrincipalSource) Claims(ctx context.Context) map[string]any {
	result := make(map[string]any)

	claims := jwt.CustomClaimsFromContext[*Claims](ctx)
	if claims == nil {
		return result
	}

	// Canonical attributes
	if claims.Actor != "" {
		result["username"] = claims.Actor
	}

	// Raw JWT claim names — use these in ClaimRoleMapper rules for precise matching.
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

// IsService returns true for any valid GitHub Actions token, as these represent
// automated workflow identities rather than human users.
func (s *PrincipalSource) IsService(ctx context.Context) bool {
	return jwt.CustomClaimsFromContext[*Claims](ctx) != nil
}


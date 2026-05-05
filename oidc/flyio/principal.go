package flyio

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dioad/auth/jwt"
	"github.com/dioad/auth/mapper"
)

// PrincipalSource extracts principal identity from Fly.io OIDC tokens.
type PrincipalSource struct {
	// RoleMapper maps raw Fly.io JWT claims to internal role strings.
	// When nil, Roles returns nil.
	RoleMapper mapper.Mapper
}

// Roles returns the internal roles derived from Fly.io claims via the configured
// RoleMapper. Returns nil when no mapper is set.
func (s *PrincipalSource) Roles(ctx context.Context) []string {
	if s.RoleMapper == nil {
		return nil
	}
	return s.RoleMapper.MapRoles(s.Claims(ctx))
}

func (s *PrincipalSource) Extract(ctx context.Context, _ *http.Request) (string, error) {
	claims := jwt.RegisteredClaimsFromContext(ctx)
	if claims != nil {
		return claims.Subject, nil
	}
	return "", fmt.Errorf("no principal found")
}

func (s *PrincipalSource) Name() string {
	return "flyio"
}

// Claims returns the Fly.io token claims as a map. Canonical attribute keys
// (e.g. "username") are included alongside raw Fly.io claim names so that
// ClaimRoleMapper rules can reference either form.
func (s *PrincipalSource) Claims(ctx context.Context) map[string]any {
	result := make(map[string]any)

	registered := jwt.RegisteredClaimsFromContext(ctx)
	if registered != nil && registered.Subject != "" {
		result["username"] = registered.Subject
	}

	claims := jwt.CustomClaimsFromContext[*CustomClaims](ctx)
	if claims != nil {
		result["app_id"] = claims.AppId
		result["app_name"] = claims.AppName
		result["image"] = claims.Image
		result["image_digest"] = claims.ImageDigest
		result["machine_id"] = claims.MachineId
		result["machine_name"] = claims.MachineName
		result["machine_version"] = claims.MachineVersion
		result["org_id"] = claims.OrgId
		result["org_name"] = claims.OrgName
		result["region"] = claims.Region
	}

	return result
}

// IsService returns true for any valid Fly.io token, as these represent machine identities.
func (s *PrincipalSource) IsService(ctx context.Context) bool {
	return jwt.CustomClaimsFromContext[*CustomClaims](ctx) != nil
}


package flyio

import (
	"context"
	"maps"

	"github.com/dioad/auth/authctx"
	"github.com/dioad/auth/jwt"
	"github.com/dioad/auth/mapper"
	"github.com/dioad/auth/oidc/oidcutil"
)

// HasValidClaims reports whether claims contains enough Fly.io-specific fields
// to be treated as a Fly.io OIDC token validated by a generic JWT middleware.
// It requires the machine-unique app_id plus at least one additional machine
// identifier to reduce false positives.
func HasValidClaims(claims map[string]any) bool {
	if !oidcutil.HasNonEmptyString(claims, "app_id") {
		return false
	}
	return oidcutil.HasAnyNonEmptyString(claims, "machine_id", "machine_name", "machine_version", "image", "image_digest")
}

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

// Extract returns the principal subject from a Fly.io token. It first attempts
// the typed-claims path (JWT middleware configured with a Fly.io validator), then
// falls back to fingerprinting generic validated claims stored by a non-typed
// JWT middleware.
func (s *PrincipalSource) Extract(ctx context.Context) (string, error) {
	// Typed path: JWT middleware configured with a Fly.io-specific validator.
	if claims := jwt.CustomClaimsFromContext[*Claims](ctx); claims != nil {
		registered := jwt.RegisteredClaimsFromContext(ctx)
		if registered == nil {
			return "", nil
		}
		return registered.Subject, nil
	}
	// Generic path: JWT middleware using a generic validator. Fingerprint the
	// custom claims map to confirm this is a Fly.io token before extracting.
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
	return "flyio"
}

// Claims returns the Fly.io token claims as a map. Canonical attribute keys
// (e.g. "username") are included alongside raw Fly.io claim names so that
// ClaimRoleMapper rules can reference either form.
func (s *PrincipalSource) Claims(ctx context.Context) map[string]any {
	result := make(map[string]any)

	// Typed path.
	registered := jwt.RegisteredClaimsFromContext(ctx)
	if registered != nil && registered.Subject != "" {
		result["username"] = registered.Subject
	}
	if claims := jwt.CustomClaimsFromContext[*Claims](ctx); claims != nil {
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
		return result
	}

	// Generic path: include all claims from the context custom claims map.
	custom, ok := authctx.AuthenticatedCustomClaimsFromContext(ctx)
	if !ok || !HasValidClaims(custom) {
		return result
	}
	maps.Copy(result, custom)
	if _, exists := result["username"]; !exists {
		if principal, ok := authctx.AuthenticatedPrincipalFromContext(ctx); ok && principal != "" {
			result["username"] = principal
		}
	}

	return result
}

// IsService returns true for any valid Fly.io token, as these represent machine identities.
func (s *PrincipalSource) IsService(ctx context.Context) bool {
	if jwt.CustomClaimsFromContext[*Claims](ctx) != nil {
		return true
	}
	custom, _ := authctx.AuthenticatedCustomClaimsFromContext(ctx)
	return HasValidClaims(custom)
}

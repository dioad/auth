package flyio

import (
	"context"
	"maps"

	"github.com/dioad/auth/authctx"
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

// ClaimsMap implements oidcutil.ClaimsMapper, flattening the typed Fly.io
// claims. subject (the token's registered "sub" claim) seeds "username" when
// present.
func (c *Claims) ClaimsMap(subject string) map[string]any {
	result := make(map[string]any, 11)
	if subject != "" {
		result["username"] = subject
	}
	result["app_id"] = c.AppId
	result["app_name"] = c.AppName
	result["image"] = c.Image
	result["image_digest"] = c.ImageDigest
	result["machine_id"] = c.MachineId
	result["machine_name"] = c.MachineName
	result["machine_version"] = c.MachineVersion
	result["org_id"] = c.OrgId
	result["org_name"] = c.OrgName
	result["region"] = c.Region
	return result
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
	return oidcutil.GenericRoles(s.RoleMapper, s.Claims(ctx))
}

// Extract returns the principal subject from a Fly.io token. It first attempts
// the typed-claims path (JWT middleware configured with a Fly.io validator), then
// falls back to fingerprinting generic validated claims stored by a non-typed
// JWT middleware.
func (s *PrincipalSource) Extract(ctx context.Context) (string, error) {
	return oidcutil.GenericExtract[Claims](ctx, HasValidClaims)
}

func (s *PrincipalSource) Name() string {
	return "flyio"
}

// Claims returns the Fly.io token claims as a map. Canonical attribute keys
// (e.g. "username") are included alongside raw Fly.io claim names so that
// ClaimRoleMapper rules can reference either form.
func (s *PrincipalSource) Claims(ctx context.Context) map[string]any {
	return oidcutil.GenericClaims[Claims](ctx, HasValidClaims, genericClaims)
}

// IsService returns true for any valid Fly.io token, as these represent machine identities.
func (s *PrincipalSource) IsService(ctx context.Context) bool {
	return oidcutil.GenericIsService[Claims](ctx, HasValidClaims)
}

// genericClaims builds the fallback-path Claims() result: the raw custom
// claims map, seeded with a canonical "username" key when missing.
func genericClaims(ctx context.Context, custom map[string]any) map[string]any {
	result := make(map[string]any, len(custom)+1)
	maps.Copy(result, custom)
	if _, exists := result["username"]; !exists {
		if principal, ok := authctx.AuthenticatedPrincipalFromContext(ctx); ok && principal != "" {
			result["username"] = principal
		}
	}
	return result
}

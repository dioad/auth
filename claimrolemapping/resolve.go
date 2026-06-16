package claimrolemapping

import (
	"maps"

	"github.com/dioad/auth"
	"github.com/dioad/auth/authz"
	"github.com/rs/zerolog"
)

// buildMapper constructs an auth.ClaimRoleMapper for the given source's filtered
// mapping rules. Role names are resolved through the policy alias table at
// construction time so principals carry canonical role names at request time.
// Returns nil when mappings is empty so that the PrincipalSource skips mapper
// invocation entirely.
//
// When any rule has Debug enabled a debugAwareMapper is returned so that
// per-request structured logging is active for that source.
func buildMapper(mappings []ClaimRoleMappingConfig, policy authz.PolicyMetadata, source string, logger zerolog.Logger) auth.ClaimRoleMapper {
	if len(mappings) == 0 {
		return nil
	}
	resolved := resolveClaimRoleMappingRoles(mappings, policy, source, logger)
	for _, m := range resolved {
		if m.Debug {
			return &debugAwareMapper{mappings: resolved, source: source, logger: logger}
		}
	}
	authMappings := make([]auth.ClaimRoleMapping, len(resolved))
	for i, m := range resolved {
		authMappings[i] = toAuthMapping(m)
	}
	return auth.NewClaimRoleMapper(authMappings)
}

// resolveClaimRoleMappingRoles returns deep copies of mappings with each Role
// field resolved through the policy alias table. Unknown roles emit a Warn log
// and are left unchanged; they will silently fail to match any capabilities.
// Rules with no claim predicates emit a Warn because they match every principal.
func resolveClaimRoleMappingRoles(mappings []ClaimRoleMappingConfig, policy authz.PolicyMetadata, source string, logger zerolog.Logger) []ClaimRoleMappingConfig {
	resolved := make([]ClaimRoleMappingConfig, len(mappings))
	for i, m := range mappings {
		c := m
		// Deep-copy the Claims map so resolved entries do not share state with
		// the input slice.
		if m.Claims != nil {
			c.Claims = make(map[string]string, len(m.Claims))
			maps.Copy(c.Claims, m.Claims)
		}
		resolved[i] = c
	}
	for i, m := range resolved {
		if len(m.Claims) == 0 {
			logger.Warn().
				Str("source", source).
				Str("role", m.Role).
				Msg("claim-role-mapping: rule has no claim predicates — it will match every principal; review your configuration")
		}
		role := authz.Role(m.Role)
		if _, isCanonical := policy.RoleCapabilities[role]; isCanonical {
			continue
		}
		if canonical, ok := policy.RoleAliases[m.Role]; ok {
			resolved[i].Role = string(canonical)
			continue
		}
		logger.Warn().
			Str("source", source).
			Str("role", m.Role).
			Msg("claim-role-mapping: unknown role — principals with this role may be denied; check your configuration")
	}
	return resolved
}

// filterMappings returns entries whose Source matches the named source, plus
// entries with an empty Source which match any source.
func filterMappings(mappings []ClaimRoleMappingConfig, source string) []ClaimRoleMappingConfig {
	var result []ClaimRoleMappingConfig
	for _, m := range mappings {
		if m.Source == "" || m.Source == source {
			result = append(result, m)
		}
	}
	return result
}

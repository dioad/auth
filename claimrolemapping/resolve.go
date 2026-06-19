package claimrolemapping

import (
	"maps"

	"github.com/dioad/auth"
	"github.com/rs/zerolog"
)

// buildMapper constructs an auth.ClaimRoleMapper for the given source's filtered
// mapping rules. Returns nil when mappings is empty so that the PrincipalSource
// skips mapper invocation entirely.
//
// When any rule has Debug enabled a debugAwareMapper is returned so that
// per-request structured logging is active for that source.
func buildMapper(mappings []ClaimRoleMappingConfig, source string, logger zerolog.Logger) auth.ClaimRoleMapper {
	if len(mappings) == 0 {
		return nil
	}
	resolved := resolveClaimRoleMappingRoles(mappings, source, logger)
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

// resolveClaimRoleMappingRoles returns deep copies of mappings. Rules with no
// claim predicates emit a Warn because they match every principal.
func resolveClaimRoleMappingRoles(mappings []ClaimRoleMappingConfig, source string, logger zerolog.Logger) []ClaimRoleMappingConfig {
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
	for _, m := range resolved {
		if len(m.Claims) == 0 {
			logger.Warn().
				Str("source", source).
				Str("role", m.Role).
				Msg("claim-role-mapping: rule has no claim predicates — it will match every principal; review your configuration")
		}
	}
	return resolved
}

// ValidateRoleMappings returns a warning string for each role name in mappings
// that does not appear in knownRoles. Call at application startup and log the
// results at Warn level to surface misconfigured claim-role mappings early.
//
// knownRoles should include both canonical role names and alias names from the
// authoriser's PolicyMetadata (convert RoleCapabilities keys and RoleAliases
// keys to []string before calling).
func ValidateRoleMappings(mappings []ClaimRoleMappingConfig, knownRoles []string) []string {
	known := make(map[string]struct{}, len(knownRoles))
	for _, r := range knownRoles {
		known[r] = struct{}{}
	}
	var warnings []string
	for _, m := range mappings {
		if _, ok := known[m.Role]; !ok {
			warnings = append(warnings, "claim-role-mapping: unknown role "+m.Role+" — principals with this role may be denied; check your configuration")
		}
	}
	return warnings
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

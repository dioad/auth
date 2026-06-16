package claimrolemapping

import (
	"fmt"

	"github.com/dioad/auth"
	"github.com/rs/zerolog"
)

// Compile-time assertion that *debugAwareMapper satisfies auth.ClaimRoleMapper.
var _ auth.ClaimRoleMapper = (*debugAwareMapper)(nil)

// debugAwareMapper implements auth.ClaimRoleMapper with optional per-rule
// structured debug logging via zerolog.
//
// When Debug is set on a ClaimRoleMappingConfig, MapRoles emits per-rule
// zerolog debug events recording the required claims, the incoming claim values,
// the match decision, and — on mismatch — which predicate failed and why.
// Claim values are only logged for rules that have Debug enabled, so sensitive
// claims from non-debug rules are not exposed in the log output.
//
// Debug must not be enabled in production as evaluated claim values are
// included in the per-rule log events.
type debugAwareMapper struct {
	mappings []ClaimRoleMappingConfig
	source   string
	logger   zerolog.Logger
}

// MapRoles evaluates each mapping rule against claims, emitting structured debug
// events for rules that have Debug enabled.
func (m *debugAwareMapper) MapRoles(claims map[string]any) []string {
	m.logger.Debug().
		Str("source", m.source).
		Int("rule_count", len(m.mappings)).
		Msg("claim-role-mapping: evaluating claims")

	var roles []string
	for _, rule := range m.mappings {
		matched, failedClaim, want, got := evalMapping(claims, rule.Claims)
		if matched {
			roles = append(roles, rule.Role)
			if rule.Debug {
				m.logger.Debug().
					Str("source", m.source).
					Str("role", rule.Role).
					Interface("required_claims", rule.Claims).
					Interface("claims", claims).
					Msg("claim-role-mapping: rule matched, role granted")
			}
			continue
		}
		if rule.Debug {
			evt := m.logger.Debug().
				Str("source", m.source).
				Str("role", rule.Role).
				Interface("required_claims", rule.Claims).
				Interface("claims", claims)
			if failedClaim != "" {
				evt = evt.
					Str("failed_claim", failedClaim).
					Str("want", want).
					Str("got", got)
			}
			evt.Msg("claim-role-mapping: rule did not match")
		}
	}

	m.logger.Debug().
		Str("source", m.source).
		Strs("roles_granted", roles).
		Msg("claim-role-mapping: evaluation complete")

	return roles
}

// evalMapping reports whether all claim predicates in required are satisfied by
// claims. On mismatch it returns the first failing claim key, the expected value
// (want), and the observed value (got). Got is "<missing>" when the key is
// absent, "<empty>" when a wildcard sees an empty string, and "<type:T>" when
// the value is not a string.
func evalMapping(claims map[string]any, required map[string]string) (matched bool, failedClaim, want, got string) {
	for key, wantVal := range required {
		val, ok := claims[key]
		if !ok {
			return false, key, wantVal, "<missing>"
		}
		s, ok := val.(string)
		if !ok {
			return false, key, wantVal, fmt.Sprintf("<type:%T>", val)
		}
		if wantVal == "*" {
			if s == "" {
				return false, key, "*", "<empty>"
			}
			continue
		}
		if s != wantVal {
			return false, key, wantVal, s
		}
	}
	return true, "", "", ""
}

// toAuthMapping converts a ClaimRoleMappingConfig to the auth.ClaimRoleMapping
// type used by auth.NewClaimRoleMapper, stripping the Source and Debug fields.
func toAuthMapping(c ClaimRoleMappingConfig) auth.ClaimRoleMapping {
	return auth.ClaimRoleMapping{Claims: c.Claims, Role: c.Role}
}

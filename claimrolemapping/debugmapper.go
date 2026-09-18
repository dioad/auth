package claimrolemapping

import (
	"fmt"

	"github.com/dioad/auth"
	"github.com/dioad/auth/mapper"
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

// evalMapping reports whether all claim predicates in required are satisfied
// by claims, using the same matching semantics as mapper.MatchesValue: string
// equality, wildcard "*", or array-membership for a []any/[]string claim (as
// produced by decoding a JSON array such as Keycloak's "groups"/"roles"
// list). On mismatch it returns the first failing claim key, the expected
// value (want), and a description of the observed value (got): "<missing>"
// when the key is absent, "<empty>" when a wildcard sees an empty string, the
// array's contents when an array claim doesn't contain want, and "<type:T>"
// for any other type MatchesValue never matches (e.g. a number or bool).
func evalMapping(claims map[string]any, required map[string]string) (matched bool, failedClaim, want, got string) {
	for key, wantVal := range required {
		val, ok := claims[key]
		if !ok {
			return false, key, wantVal, "<missing>"
		}
		if mapper.MatchesValue(val, wantVal) {
			continue
		}
		return false, key, wantVal, describeMismatch(val, wantVal)
	}
	return true, "", "", ""
}

// describeMismatch renders val for a debug log's "got" field after
// mapper.MatchesValue has already reported that it does not satisfy want.
func describeMismatch(val any, want string) string {
	switch v := val.(type) {
	case string:
		if want == "*" {
			return "<empty>"
		}
		return v
	case []any, []string:
		return fmt.Sprintf("%v", v)
	default:
		return fmt.Sprintf("<type:%T>", val)
	}
}

// toAuthMapping converts a ClaimRoleMappingConfig to the auth.ClaimRoleMapping
// type used by auth.NewClaimRoleMapper, stripping the Source and Debug fields.
func toAuthMapping(c ClaimRoleMappingConfig) auth.ClaimRoleMapping {
	return auth.ClaimRoleMapping{Claims: c.Claims, Role: c.Role}
}

// Package mapper provides claim-based role mapping for PrincipalSource implementations.
// It allows applications to configure rules that grant internal roles to service
// identities based on JWT claim values, without requiring the IdP to support
// custom role claims.
package mapper

import "slices"

// ClaimRoleMapping maps a set of claim predicates to an internal role.
// All claim predicates must match (AND semantics).
type ClaimRoleMapping struct {
	// Claims maps claim key → required value.
	// Keys may be canonical attribute names (e.g. "primary_email", "username")
	// or raw JWT claim names specific to the IdP (e.g. "repository", "app_name").
	// A value of "*" matches any non-empty string, or any non-empty array.
	//
	// The corresponding claim value may be a plain string, or an array (e.g.
	// []any, as produced by decoding a JSON array such as Keycloak's "groups"
	// or "roles" claim). For an array claim, the predicate matches when want
	// equals any one element.
	Claims map[string]string

	// Role is the role string granted when all claim predicates match.
	Role string
}

// Mapper maps a claims map to a list of roles.
type Mapper interface {
	MapRoles(claims map[string]any) []string
}

type claimRoleMapper struct {
	mappings []ClaimRoleMapping
}

// New creates a Mapper from a list of ClaimRoleMapping rules.
// Each rule is evaluated independently; all matching roles are returned.
// Returns nil if mappings is empty.
func New(mappings []ClaimRoleMapping) Mapper {
	if len(mappings) == 0 {
		return nil
	}
	return &claimRoleMapper{mappings: mappings}
}

// MapRoles evaluates each mapping against the provided claims and returns all
// roles whose predicates are satisfied. Returns nil if no mappings match.
func (m *claimRoleMapper) MapRoles(claims map[string]any) []string {
	var roles []string
	for _, mapping := range m.mappings {
		if matchesAll(claims, mapping.Claims) {
			roles = append(roles, mapping.Role)
		}
	}
	return roles
}

// matchesAll returns true when every predicate in required is satisfied by the
// corresponding value in claims.
func matchesAll(claims map[string]any, required map[string]string) bool {
	for key, want := range required {
		val, ok := claims[key]
		if !ok {
			return false
		}
		if !matchesValue(val, want) {
			return false
		}
	}
	return true
}

// matchesValue reports whether a single claim value satisfies want. val may
// be a plain string, or an array of strings — []any (as produced by decoding
// a JSON array claim, e.g. Keycloak's "groups"/"roles" list) or []string. Any
// other type never matches. want == "*" matches a non-empty string, or a
// non-empty array; any other want requires an exact match against the
// string, or against at least one array element.
func matchesValue(val any, want string) bool {
	switch v := val.(type) {
	case string:
		if want == "*" {
			return v != ""
		}
		return v == want
	case []any:
		if want == "*" {
			return len(v) > 0
		}
		for _, elem := range v {
			if s, ok := elem.(string); ok && s == want {
				return true
			}
		}
		return false
	case []string:
		if want == "*" {
			return len(v) > 0
		}
		return slices.Contains(v, want)
	default:
		return false
	}
}

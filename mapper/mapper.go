// Package mapper provides claim-based role mapping for PrincipalSource implementations.
// It allows applications to configure rules that grant internal roles to service
// identities based on JWT claim values, without requiring the IdP to support
// custom role claims.
package mapper

// ClaimRoleMapping maps a set of claim predicates to an internal role.
// All claim predicates must match (AND semantics).
type ClaimRoleMapping struct {
	// Claims maps claim key → required value.
	// Keys may be canonical attribute names (e.g. "primary_email", "username")
	// or raw JWT claim names specific to the IdP (e.g. "repository", "app_name").
	// A value of "*" matches any non-empty string.
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
		s, ok := val.(string)
		if !ok {
			return false
		}
		if want == "*" {
			if s == "" {
				return false
			}
			continue
		}
		if s != want {
			return false
		}
	}
	return true
}

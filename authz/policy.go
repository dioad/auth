package authz

import (
	"maps"
	"slices"

	"github.com/dioad/auth"
)

// Role is an internal policy role name.
type Role string

// PolicyMetadata describes a static role→capability policy used to
// configure [RoleAuthorizer] and [CasbinAuthorizer].
type PolicyMetadata struct {
	// RoleCapabilities maps each internal Role to the set of Capabilities it grants.
	RoleCapabilities map[Role][]Capability

	// RoleAliases maps external role/group names (from IdP tokens) to internal
	// Roles. Only aliases listed here are accepted; unmapped external roles are
	// rejected. This prevents a token from accidentally carrying an internal role
	// name (e.g. "admin") and gaining elevated privileges.
	RoleAliases map[string]Role
}

// CloneMetadata returns a deep copy of m.
func CloneMetadata(m PolicyMetadata) PolicyMetadata {
	rc := make(map[Role][]Capability, len(m.RoleCapabilities))
	for role, caps := range m.RoleCapabilities {
		rc[role] = slices.Clone(caps)
	}
	return PolicyMetadata{
		RoleCapabilities: rc,
		RoleAliases:      maps.Clone(m.RoleAliases),
	}
}

// MergeRoleAliases returns a copy of meta with the provided aliases merged in.
// Existing aliases are preserved; entries in aliases override duplicates.
func MergeRoleAliases(meta PolicyMetadata, aliases map[string]Role) PolicyMetadata {
	merged := CloneMetadata(meta)
	if merged.RoleAliases == nil {
		merged.RoleAliases = make(map[string]Role, len(aliases))
	}
	maps.Copy(merged.RoleAliases, aliases)
	return merged
}

// principalRoles resolves the principal's token roles to internal Roles via the
// provided alias map. Unmapped external roles are silently dropped, preventing
// a principal from using an arbitrary string to claim an internal role.
func principalRoles(principalCtx *auth.PrincipalContext, aliases map[string]Role) []Role {
	roles := make([]Role, 0, len(principalCtx.Roles))
	for _, r := range principalCtx.Roles {
		internalRole, ok := aliases[r]
		if !ok {
			continue
		}
		roles = append(roles, internalRole)
	}
	return roles
}

// privilegeSetForRoles builds a PrivilegeSet by unioning the capabilities of
// each role in roles from the given role→capabilities map.
func privilegeSetForRoles(roles []Role, roleCapabilities map[Role][]Capability) *PrivilegeSet {
	ps := NewPrivilegeSet()
	for _, role := range roles {
		for _, cap := range roleCapabilities[role] {
			ps.Grant(cap)
		}
	}
	return ps
}

// canFromPrivileges implements the default Can() logic for authorizers that
// delegate to Privileges().Has(). It handles nil principal and nil Privilege.
func canFromPrivileges(principalCtx *auth.PrincipalContext, cap Capability, privs Privilege, err error) (*Decision, error) {
	if principalCtx == nil {
		return deny(ReasonDeniedNilPrincipal, cap), ErrForbidden
	}
	if err != nil {
		return nil, err
	}
	if privs == nil {
		return deny(ReasonDeniedNoRoles, cap), ErrForbidden
	}
	if !privs.Has(cap) {
		return deny(ReasonDeniedNoPermission, cap), ErrForbidden
	}
	return allow(ReasonGranted, "", cap), nil
}

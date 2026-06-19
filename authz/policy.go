package authz

import (
	"context"
	"maps"
	"slices"

	"github.com/rs/zerolog"

	"github.com/dioad/auth"
)

// Role is an internal policy role name.
type Role string

// PolicyMetadata describes a static role→capability policy used to
// configure [RoleAuthorizer] and [CasbinAuthorizer].
//
// PolicyMetadata is treated as immutable after construction. Authorizer
// constructors deep-copy the value via [CloneMetadata]; callers who need a
// mutable copy after that point should call [CloneMetadata] themselves.
type PolicyMetadata struct {
	// RoleCapabilities maps each internal Role to the set of Capabilities it grants.
	RoleCapabilities map[Role][]Capability

	// RoleAliases maps external role/group names (from IdP tokens) to internal
	// Roles. Canonical internal role names are accepted when they appear in
	// RoleCapabilities; otherwise only aliases listed here are accepted, and
	// unrecognised role strings are ignored.
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

// principalRoles resolves the principal's token roles to internal Roles.
// A role string is accepted if it is a canonical role name (present as a key in
// capabilities) or if it maps to one via the alias table. Canonical names take
// priority, so self-referential alias entries are unnecessary. Unrecognised
// role strings are dropped and logged at trace level for operator visibility.
func principalRoles(ctx context.Context, principalCtx *auth.PrincipalContext, aliases map[string]Role, capabilities map[Role][]Capability) []Role {
	roles := make([]Role, 0, len(principalCtx.Roles))
	for _, r := range principalCtx.Roles {
		role := Role(r)
		if _, isCanonical := capabilities[role]; isCanonical {
			roles = append(roles, role)
			continue
		}
		if mapped, ok := aliases[r]; ok {
			roles = append(roles, mapped)
		} else {
			zerolog.Ctx(ctx).Trace().
				Str("principal", principalCtx.ID).
				Str("role", r).
				Msg("authz: dropping unrecognised role")
		}
	}
	return roles
}

// privilegeSetForRoles builds a PrivilegeSet by unioning the capabilities of
// each role in roles from the given role→capabilities map.
func privilegeSetForRoles(roles []Role, roleCapabilities map[Role][]Capability) *PrivilegeSet {
	ps := NewPrivilegeSet()
	for _, role := range roles {
		for _, capability := range roleCapabilities[role] {
			ps.Grant(capability)
		}
	}
	return ps
}

// canFromPrivileges implements the default Can() logic for authorizers that
// delegate to Privileges().Has(). It handles nil principal and nil Privilege.
func canFromPrivileges(principalCtx *auth.PrincipalContext, cap Capability, privs Privilege, err error) (*Decision, error) {
	if principalCtx == nil {
		return deny(ReasonDeniedNilPrincipal, cap), ErrUnauthorized
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

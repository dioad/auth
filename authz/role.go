package authz

import (
	"context"

	"github.com/dioad/auth"
)

// RoleAuthorizer is an [Authorizer] backed by an in-memory role→capability map.
// Matching roles are unioned to form the principal's privilege set. It is
// suitable for static config-driven deployments and unit tests. For production
// use with complex policies, prefer [CasbinAuthorizer].
type RoleAuthorizer struct {
	metadata PolicyMetadata
}

// NewRoleAuthorizer creates a RoleAuthorizer from the given PolicyMetadata.
func NewRoleAuthorizer(metadata PolicyMetadata) *RoleAuthorizer {
	return &RoleAuthorizer{metadata: CloneMetadata(metadata)}
}

// Privileges resolves the principal's roles via RoleAliases and returns the
// union of all matching role capabilities. Returns nil when the principal has
// no recognised roles.
func (a *RoleAuthorizer) Privileges(_ context.Context, principalCtx *auth.PrincipalContext) (Privilege, error) {
	if principalCtx == nil {
		return nil, nil
	}
	roles := principalRoles(principalCtx, a.metadata.RoleAliases)
	if len(roles) == 0 {
		return nil, nil
	}
	return NewWildcardPrivilege(privilegeSetForRoles(roles, a.metadata.RoleCapabilities)), nil
}

// Can checks whether the principal's union of role capabilities includes cap.
func (a *RoleAuthorizer) Can(ctx context.Context, principalCtx *auth.PrincipalContext, cap Capability) (*Decision, error) {
	privs, err := a.Privileges(ctx, principalCtx)
	return canFromPrivileges(principalCtx, cap, privs, err)
}

// Metadata returns the policy metadata.
func (a *RoleAuthorizer) Metadata() PolicyMetadata {
	return CloneMetadata(a.metadata)
}

package authz

import (
	"context"

	"github.com/dioad/auth"
)

// MapAuthorizer is an [Authorizer] backed by a principal-ID → [PrivilegeSet]
// map. It is useful for inline test configs and simple static deployments where
// each principal's capabilities are enumerated directly.
//
// If a principal ID is not found in the map, Privileges returns nil (no
// capabilities). In a [MultiAuthorizer] chain this causes the next backend to
// be tried.
type MapAuthorizer struct {
	privileges map[string]*PrivilegeSet
	metadata   PolicyMetadata
}

// NewMapAuthorizer creates a MapAuthorizer with the given principal→privileges
// map and policy metadata (used for Metadata() introspection).
func NewMapAuthorizer(privileges map[string]*PrivilegeSet, metadata PolicyMetadata) *MapAuthorizer {
	// Defensive copy of the map keys; PrivilegeSets are not deep-copied as
	// they are treated as immutable after construction.
	cp := make(map[string]*PrivilegeSet, len(privileges))
	for k, v := range privileges {
		cp[k] = v
	}
	return &MapAuthorizer{privileges: cp, metadata: CloneMetadata(metadata)}
}

// Privileges looks up the principal's ID in the map. Returns nil when not found.
func (a *MapAuthorizer) Privileges(_ context.Context, principalCtx *auth.PrincipalContext) (Privilege, error) {
	if principalCtx == nil {
		return nil, nil
	}
	ps, ok := a.privileges[principalCtx.ID]
	if !ok {
		return nil, nil
	}
	return ps, nil
}

// Can checks whether the principal's mapped PrivilegeSet contains cap.
func (a *MapAuthorizer) Can(ctx context.Context, principalCtx *auth.PrincipalContext, cap Capability) (*Decision, error) {
	privs, err := a.Privileges(ctx, principalCtx)
	return canFromPrivileges(principalCtx, cap, privs, err)
}

// Metadata returns the policy metadata.
func (a *MapAuthorizer) Metadata() PolicyMetadata {
	return CloneMetadata(a.metadata)
}

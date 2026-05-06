package authz

import (
	"context"

	"github.com/dioad/auth"
)

// AllowAllAuthorizer is an [Authorizer] that grants every capability. It is
// intended for dev/test environments where RBAC enforcement is explicitly
// disabled via configuration. It must never be used in production.
type AllowAllAuthorizer struct {
	metadata PolicyMetadata
}

// NewAllowAllAuthorizer returns an AllowAllAuthorizer with the given policy
// metadata (used only for Metadata() introspection).
func NewAllowAllAuthorizer(metadata PolicyMetadata) *AllowAllAuthorizer {
	return &AllowAllAuthorizer{metadata: CloneMetadata(metadata)}
}

// Privileges returns a Privilege that grants every capability.
func (a *AllowAllAuthorizer) Privileges(_ context.Context, _ *auth.PrincipalContext) (Privilege, error) {
	return allowAllPrivilege{}, nil
}

// Can always returns an allowed Decision with ReasonAllowAll.
func (a *AllowAllAuthorizer) Can(_ context.Context, _ *auth.PrincipalContext, cap Capability) (*Decision, error) {
	return allow(ReasonAllowAll, "", cap), nil
}

// Metadata returns the policy metadata provided at construction.
func (a *AllowAllAuthorizer) Metadata() PolicyMetadata {
	return CloneMetadata(a.metadata)
}

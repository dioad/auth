package authz

import (
	"context"

	"github.com/dioad/auth"
)

// MultiAuthorizer chains multiple [Authorizer] backends. [Privileges] returns
// the result from the first backend that returns a non-nil Privilege; [Can]
// similarly short-circuits on the first non-nil Privilege result. If all
// backends return nil Privileges the principal is denied.
//
// This matches the connect MultiAuthoriser semantics and is useful for
// composing inline + dynamic backends.
type MultiAuthorizer struct {
	authorizers []Authorizer
	metadata    PolicyMetadata
}

// NewMultiAuthorizer creates a MultiAuthorizer from the provided backends.
// The metadata from the first backend is used for Metadata() introspection.
func NewMultiAuthorizer(authorizers ...Authorizer) *MultiAuthorizer {
	var meta PolicyMetadata
	if len(authorizers) > 0 {
		meta = authorizers[0].Metadata()
	}
	return &MultiAuthorizer{authorizers: authorizers, metadata: meta}
}

// Privileges iterates the backends in order and returns the first non-nil
// Privilege. Returns nil when no backend recognises the principal.
func (m *MultiAuthorizer) Privileges(ctx context.Context, principalCtx *auth.PrincipalContext) (Privilege, error) {
	for _, a := range m.authorizers {
		privs, err := a.Privileges(ctx, principalCtx)
		if privs != nil || err != nil {
			return privs, err
		}
	}
	return nil, nil
}

// Can checks whether the first backend that returns a non-nil Privilege grants
// cap. If no backend recognises the principal, the request is denied.
func (m *MultiAuthorizer) Can(ctx context.Context, principalCtx *auth.PrincipalContext, cap Capability) (*Decision, error) {
	privs, err := m.Privileges(ctx, principalCtx)
	return canFromPrivileges(principalCtx, cap, privs, err)
}

// Metadata returns the metadata from the first backend, or an empty
// PolicyMetadata when no backends are configured.
func (m *MultiAuthorizer) Metadata() PolicyMetadata {
	return CloneMetadata(m.metadata)
}

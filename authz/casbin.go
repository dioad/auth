package authz

import (
	"context"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/rs/zerolog"

	"github.com/dioad/auth"
)

// casbinModel is the Casbin RBAC model used by CasbinAuthorizer.
// Policy format: p = role, resource, action
// Role assignments are loaded from PolicyMetadata.RoleAliases.
// The "any" action wildcard grants all actions on the given resource.
const casbinModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && (r.act == p.act || p.act == "any")
`

// CasbinAuthorizer is an [Authorizer] backed by Casbin v2. It is the
// recommended production backend for both connect and connect-control.
//
// Policy rules are loaded from [PolicyMetadata.RoleCapabilities] at
// construction. [Can] uses Casbin enforce for efficient per-action checks
// and records the granting role in the returned [Decision].
type CasbinAuthorizer struct {
	enforcer *casbin.Enforcer
	metadata PolicyMetadata
}

// NewCasbinAuthorizer creates a CasbinAuthorizer from the given PolicyMetadata.
// Each capability in RoleCapabilities is split on ":" to derive the Casbin
// (obj, act) pair and loaded as a policy rule. Returns an error if the Casbin
// model or any policy rule cannot be created.
func NewCasbinAuthorizer(metadata PolicyMetadata) (*CasbinAuthorizer, error) {
	m, err := model.NewModelFromString(casbinModel)
	if err != nil {
		return nil, fmt.Errorf("create casbin model: %w", err)
	}

	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, fmt.Errorf("create casbin enforcer: %w", err)
	}

	for role, caps := range metadata.RoleCapabilities {
		for _, cap := range caps {
			obj, act, ok := strings.Cut(string(cap), ":")
			if !ok {
				return nil, fmt.Errorf("capability %q missing ':' separator — use Permission() or FeatureCapability() constructors", cap)
			}
			if _, err = enforcer.AddPolicy(string(role), obj, act); err != nil {
				return nil, fmt.Errorf("add casbin policy %s %s %s: %w", role, obj, act, err)
			}
		}
	}

	return &CasbinAuthorizer{enforcer: enforcer, metadata: CloneMetadata(metadata)}, nil
}

// Privileges resolves the principal's roles via RoleAliases and returns the
// union of all matching role capabilities as a [PrivilegeSet].
func (a *CasbinAuthorizer) Privileges(_ context.Context, principalCtx *auth.PrincipalContext) (Privilege, error) {
	if principalCtx == nil {
		return nil, nil
	}
	roles := principalRoles(principalCtx, a.metadata.RoleAliases)
	if len(roles) == 0 {
		return nil, nil
	}
	return NewWildcardPrivilege(privilegeSetForRoles(roles, a.metadata.RoleCapabilities)), nil
}

// Can checks whether the principal's roles grant cap using Casbin enforcement.
// The returned Decision includes GrantedBy — the first role that grants the
// capability — enabling fine-grained audit logging.
func (a *CasbinAuthorizer) Can(_ context.Context, principalCtx *auth.PrincipalContext, cap Capability) (*Decision, error) {
	if principalCtx == nil {
		return deny(ReasonDeniedNilPrincipal, cap), ErrForbidden
	}

	roles := principalRoles(principalCtx, a.metadata.RoleAliases)
	if len(roles) == 0 {
		return deny(ReasonDeniedNoRoles, cap), ErrForbidden
	}

	obj, act, ok := strings.Cut(string(cap), ":")
	if !ok {
		return nil, fmt.Errorf("capability %q missing ':' separator — use Permission() or FeatureCapability() constructors", cap)
	}

	for _, role := range roles {
		granted, err := a.enforcer.Enforce(string(role), obj, act)
		if err != nil {
			// Infrastructure failure — return nil Decision to distinguish from
			// a policy denial.
			return nil, fmt.Errorf("casbin enforce: %w", err)
		}
		if granted {
			return allow(ReasonGranted, role, cap), nil
		}
	}

	return deny(ReasonDeniedNoPermission, cap), ErrForbidden
}

// Metadata returns the policy metadata.
func (a *CasbinAuthorizer) Metadata() PolicyMetadata {
	return CloneMetadata(a.metadata)
}

// NewDefaultCasbinAuthorizer attempts to create a CasbinAuthorizer from the
// given metadata. If Casbin initialisation fails, it falls back to a
// [RoleAuthorizer] and logs a warning so operators can investigate.
func NewDefaultCasbinAuthorizer(metadata PolicyMetadata, logger zerolog.Logger) (Authorizer, error) {
	a, err := NewCasbinAuthorizer(metadata)
	if err != nil {
		logger.Warn().Err(err).Msg("casbin authorizer initialisation failed, falling back to role authorizer")
		return NewRoleAuthorizer(metadata), nil
	}
	return a, nil
}

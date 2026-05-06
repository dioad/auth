package authz

import "errors"

// ErrForbidden is returned by [Authorizer.Can] when a policy decision denies
// the requested capability. Use errors.Is(err, ErrForbidden) for flow control.
// A non-nil *[Decision] accompanies ErrForbidden. On infrastructure failures
// (non-policy errors), err is non-nil but *Decision is nil.
var ErrForbidden = errors.New("forbidden")

// DecisionReason is a stable string token that describes why an authorization
// decision was made. It is intended for structured audit logging; callers
// should still use errors.Is(err, ErrForbidden) for flow control.
type DecisionReason string

const (
	// ReasonAllowAll is returned by [AllowAllAuthorizer] — every capability
	// is granted regardless of principal or policy.
	ReasonAllowAll DecisionReason = "allow_all"

	// ReasonGranted means a policy rule explicitly grants the capability.
	ReasonGranted DecisionReason = "granted"

	// ReasonDeniedNilPrincipal means no principal was supplied.
	ReasonDeniedNilPrincipal DecisionReason = "denied_nil_principal"

	// ReasonDeniedNoRoles means the principal carries no roles that appear in
	// the policy's RoleAliases map. Unmapped external roles are rejected.
	ReasonDeniedNoRoles DecisionReason = "denied_no_roles"

	// ReasonDeniedNoPermission means the principal's roles are recognised but
	// none of them grant the required capability.
	ReasonDeniedNoPermission DecisionReason = "denied_no_permission"
)

// Decision records the outcome of an authorization check for audit logging.
// It is non-nil whenever the authorizer reaches a policy conclusion (allow or
// deny). It is nil only when the error is unrelated to policy — for example,
// an infrastructure failure in the underlying enforcement engine.
type Decision struct {
	// Allowed is true when the capability was granted.
	Allowed bool

	// Reason is a stable token describing the outcome.
	Reason DecisionReason

	// GrantedBy is the Role that granted the capability.
	// Empty when Allowed is false or when AllowAllAuthorizer is used.
	GrantedBy Role

	// Required is the Capability that was evaluated.
	Required Capability
}

// allow returns an allowed Decision.
func allow(reason DecisionReason, grantedBy Role, required Capability) *Decision {
	return &Decision{Allowed: true, Reason: reason, GrantedBy: grantedBy, Required: required}
}

// deny returns a denied Decision with the given reason and required capability.
func deny(reason DecisionReason, required Capability) *Decision {
	return &Decision{Allowed: false, Reason: reason, Required: required}
}

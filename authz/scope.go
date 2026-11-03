package authz

import (
	"context"
	"errors"

	"github.com/dioad/auth"
)

// CheckFunc reports whether a principal may exercise a capability. It returns
// nil when allowed, an error matching [ErrForbidden] or [ErrUnauthorized] for a
// policy outcome, and any other error for an infrastructure failure.
type CheckFunc func(ctx context.Context, principalCtx *auth.PrincipalContext, capability Capability) error

// Check reports whether principalCtx may exercise capability under a. It
// returns nil when allowed, exactly [ErrForbidden] or [ErrUnauthorized] for a
// policy denial, and any other error unchanged. A denial is reduced to the bare
// sentinel, dropping whatever detail the authorizer wrapped around it, so a
// caller can return it to a client without revealing policy internals. A nil a
// is fail-closed: every check returns [ErrForbidden], so a service constructed
// without an authorizer never silently allows access.
func Check(ctx context.Context, a Authorizer, principalCtx *auth.PrincipalContext, capability Capability) error {
	if a == nil {
		return ErrForbidden
	}
	_, err := a.Can(ctx, principalCtx, capability)
	switch {
	case errors.Is(err, ErrForbidden):
		return ErrForbidden
	case errors.Is(err, ErrUnauthorized):
		return ErrUnauthorized
	}
	return err
}

// AuthorizerCheck returns a [CheckFunc] that runs [Check] against a.
func AuthorizerCheck(a Authorizer) CheckFunc {
	return func(ctx context.Context, principalCtx *auth.PrincipalContext, capability Capability) error {
		return Check(ctx, a, principalCtx, capability)
	}
}

// PrincipalScope says whether a caller's access covers every principal's
// resources or only its own.
type PrincipalScope int

const (
	// ScopeOwn restricts access to resources owned by the calling principal.
	// It is the zero value, so an unset scope is the restrictive one.
	ScopeOwn PrincipalScope = iota
	// ScopeAll grants access to resources across all principals.
	ScopeAll
)

// String returns "own" or "all".
func (s PrincipalScope) String() string {
	if s == ScopeAll {
		return "all"
	}
	return "own"
}

// ResolveScope decides whether principalCtx gets [ScopeAll] or [ScopeOwn]
// access to a resource.
//
// allCap grants access across all principals. ownCap, if not empty, grants
// access to the caller's own resources. The rules are:
//
//   - allCap granted: ScopeAll.
//   - Nil principal and allCap not granted: the check's error is returned.
//     allCap is still checked first, so an [AllowAllAuthorizer] can answer.
//   - ownCap set: ScopeOwn if it is granted; otherwise ErrUnauthorized if the
//     own check said so, ErrForbidden if either check did, or else the own
//     check's infrastructure error.
//   - ownCap empty: an authenticated caller forbidden allCap falls back to
//     ScopeOwn with no error; any other error is returned.
//
// When an error is returned the scope is always ScopeOwn, but callers must
// treat the error as a denial and not use the scope.
func ResolveScope(
	ctx context.Context,
	principalCtx *auth.PrincipalContext,
	check CheckFunc,
	allCap Capability,
	ownCap Capability,
) (PrincipalScope, error) {
	allErr := check(ctx, principalCtx, allCap)
	if allErr == nil {
		return ScopeAll, nil
	}

	if principalCtx == nil {
		return ScopeOwn, allErr
	}

	if ownCap != "" {
		ownErr := check(ctx, principalCtx, ownCap)
		if ownErr == nil {
			return ScopeOwn, nil
		}

		switch {
		case errors.Is(ownErr, ErrUnauthorized):
			return ScopeOwn, ErrUnauthorized
		case errors.Is(allErr, ErrForbidden), errors.Is(ownErr, ErrForbidden):
			return ScopeOwn, ErrForbidden
		default:
			return ScopeOwn, ownErr
		}
	}

	if errors.Is(allErr, ErrForbidden) {
		return ScopeOwn, nil
	}
	return ScopeOwn, allErr
}

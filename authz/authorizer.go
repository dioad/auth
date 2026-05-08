package authz

import (
	"context"

	"github.com/dioad/auth"
)

// Authorizer determines whether a principal may exercise a capability.
//
// # Flow control
//
// [Can] returns a non-nil *[Decision] for every policy outcome (allow or deny).
// It returns a nil *Decision only for infrastructure failures unrelated to policy.
//
// Two sentinel errors signal distinct failure modes:
//
//   - [ErrUnauthorized] — the request could not be evaluated because there is no
//     authenticated principal (principalCtx is nil). This corresponds to an HTTP
//     401 condition.
//   - [ErrForbidden] — the principal was authenticated but the policy denied the
//     requested capability. This corresponds to an HTTP 403 condition; a non-nil
//     *Decision with audit information always accompanies this error.
//
// Example:
//
//	d, err := authorizer.Can(ctx, principalCtx, authz.Permission("tunnel", "write"))
//	if errors.Is(err, authz.ErrUnauthorized) {
//	    // no principal — redirect to login
//	}
//	if errors.Is(err, authz.ErrForbidden) {
//	    // denied by policy — d contains audit info
//	}
//
// # Connect pattern (fetch-once, check-many)
//
// [Privileges] fetches the full capability set for a principal once; the caller
// then checks individual capabilities inline using [Privilege.Has]. This is
// efficient for handlers that perform multiple capability checks:
//
//	privs, _ := authorizer.Privileges(ctx, principalCtx)
//	if privs.Has(authz.FeatureCapability("custom-domain")) { ... }
//	if privs.Has(authz.Permission("tunnel", "write")) { ... }
type Authorizer interface {
	// Privileges returns the full capability set for the principal. It returns
	// nil when the principal has no recognised roles (not an error). Callers
	// should treat a nil Privilege as "no capabilities".
	Privileges(ctx context.Context, principalCtx *auth.PrincipalContext) (Privilege, error)

	// Can checks whether the principal holds cap. A non-nil *Decision is
	// returned for every policy outcome; nil only on infrastructure errors.
	// Use errors.Is(err, ErrUnauthorized) to detect a missing principal, and
	// errors.Is(err, ErrForbidden) to detect a policy denial.
	Can(ctx context.Context, principalCtx *auth.PrincipalContext, cap Capability) (*Decision, error)

	// Metadata returns the policy metadata for introspection.
	Metadata() PolicyMetadata
}

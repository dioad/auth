package authz_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth"
	"github.com/dioad/auth/authz"
)

func TestResolveScope(t *testing.T) {
	t.Parallel()

	const (
		allCap authz.Capability = "thing:read:all"
		ownCap authz.Capability = "thing:read:own"
		noOwn  authz.Capability = ""
	)
	errInfra := errors.New("infrastructure failure")
	errOwnInfra := errors.New("own infrastructure failure")
	caller := &auth.PrincipalContext{ID: "caller"}

	// grants allows exactly the listed capabilities and returns deny for any other.
	grants := func(deny error, allowed ...authz.Capability) authz.CheckFunc {
		return func(_ context.Context, _ *auth.PrincipalContext, c authz.Capability) error {
			if slices.Contains(allowed, c) {
				return nil
			}
			return deny
		}
	}
	// byCap returns a distinct error for allCap and for every other capability.
	byCap := func(allErr, ownErr error) authz.CheckFunc {
		return func(_ context.Context, _ *auth.PrincipalContext, c authz.Capability) error {
			if c == allCap {
				return allErr
			}
			return ownErr
		}
	}

	tests := []struct {
		name      string
		principal *auth.PrincipalContext
		check     authz.CheckFunc
		ownCap    authz.Capability
		wantScope authz.PrincipalScope
		wantErr   error
	}{
		{"all granted", caller, grants(authz.ErrForbidden, allCap), ownCap, authz.ScopeAll, nil},
		{"all granted without own capability", caller, grants(authz.ErrForbidden, allCap), noOwn, authz.ScopeAll, nil},
		{"nil principal allowed by permissive authorizer", nil, grants(nil), ownCap, authz.ScopeAll, nil},
		{"nil principal unauthorized", nil, grants(authz.ErrUnauthorized), ownCap, authz.ScopeOwn, authz.ErrUnauthorized},
		{"nil principal forbidden surfaces the forbidden error", nil, grants(authz.ErrForbidden), ownCap, authz.ScopeOwn, authz.ErrForbidden},
		{"nil principal infrastructure error surfaces unchanged", nil, grants(errInfra), noOwn, authz.ScopeOwn, errInfra},
		{"nil principal forbidden without own capability gets no own-scope fallback", nil, grants(authz.ErrForbidden), noOwn, authz.ScopeOwn, authz.ErrForbidden},
		{"nil principal is not granted own scope by the own capability", nil, grants(authz.ErrForbidden, ownCap), ownCap, authz.ScopeOwn, authz.ErrForbidden},
		{"own granted only", caller, grants(authz.ErrForbidden, ownCap), ownCap, authz.ScopeOwn, nil},
		{"own capability unauthorized", caller, byCap(authz.ErrForbidden, authz.ErrUnauthorized), ownCap, authz.ScopeOwn, authz.ErrUnauthorized},
		{"neither granted is forbidden", caller, grants(authz.ErrForbidden), ownCap, authz.ScopeOwn, authz.ErrForbidden},
		{"own forbidden after infrastructure error on all", caller, byCap(errInfra, authz.ErrForbidden), ownCap, authz.ScopeOwn, authz.ErrForbidden},
		{"all forbidden after infrastructure error on own", caller, byCap(authz.ErrForbidden, errInfra), ownCap, authz.ScopeOwn, authz.ErrForbidden},
		{"infrastructure error on both surfaces the own error", caller, byCap(errInfra, errOwnInfra), ownCap, authz.ScopeOwn, errOwnInfra},
		{"forbidden without own capability falls back to own scope", caller, grants(authz.ErrForbidden), noOwn, authz.ScopeOwn, nil},
		{"wrapped forbidden without own capability falls back to own scope", caller, grants(fmt.Errorf("policy: %w", authz.ErrForbidden)), noOwn, authz.ScopeOwn, nil},
		{"unauthorized without own capability is an error", caller, grants(authz.ErrUnauthorized), noOwn, authz.ScopeOwn, authz.ErrUnauthorized},
		{"infrastructure error without own capability surfaces unchanged", caller, grants(errInfra), noOwn, authz.ScopeOwn, errInfra},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scope, err := authz.ResolveScope(context.Background(), tt.principal, tt.check, allCap, tt.ownCap)

			assert.Equal(t, tt.wantScope, scope)
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestResolveScope_ChecksOwnCapabilityOnlyWhenAllIsDenied(t *testing.T) {
	t.Parallel()

	var checked []authz.Capability
	check := func(_ context.Context, _ *auth.PrincipalContext, c authz.Capability) error {
		checked = append(checked, c)
		return nil
	}

	_, err := authz.ResolveScope(context.Background(), &auth.PrincipalContext{ID: "caller"}, check, "thing:read:all", "thing:read:own")

	require.NoError(t, err)
	assert.Equal(t, []authz.Capability{"thing:read:all"}, checked)
}

func TestPrincipalScope_ZeroValueIsOwn(t *testing.T) {
	t.Parallel()

	var scope authz.PrincipalScope

	assert.Equal(t, authz.ScopeOwn, scope)
	assert.Equal(t, "own", scope.String())
	assert.Equal(t, "all", authz.ScopeAll.String())
}

func TestAuthorizerCheck(t *testing.T) {
	t.Parallel()

	read := authz.Permission("thing", "read")
	enforcing := authz.NewMapAuthorizer(map[string]*authz.PrivilegeSet{"reader": authz.NewPrivilegeSet(read)}, authz.PolicyMetadata{})

	tests := []struct {
		name       string
		authorizer authz.Authorizer
		principal  *auth.PrincipalContext
		wantErr    error
	}{
		{"granted", enforcing, &auth.PrincipalContext{ID: "reader"}, nil},
		{"denied by policy", enforcing, &auth.PrincipalContext{ID: "stranger"}, authz.ErrForbidden},
		{"nil principal", enforcing, nil, authz.ErrUnauthorized},
		{"nil authorizer is fail-closed", nil, &auth.PrincipalContext{ID: "reader"}, authz.ErrForbidden},
		{"allow-all grants a nil principal", authz.NewAllowAllAuthorizer(authz.PolicyMetadata{}), nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := authz.AuthorizerCheck(tt.authorizer)(context.Background(), tt.principal, read)

			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// ExampleResolveScope shows a list endpoint that returns every principal's
// items to an admin and only the caller's own items to everyone else.
func ExampleResolveScope() {
	readAll := authz.Permission("usage", "read_all")
	readOwn := authz.Permission("usage", "read_own")
	authorizer := authz.NewMapAuthorizer(map[string]*authz.PrivilegeSet{
		"admin": authz.NewPrivilegeSet(readAll),
		"alice": authz.NewPrivilegeSet(readOwn),
	}, authz.PolicyMetadata{})
	check := authz.AuthorizerCheck(authorizer)

	for _, id := range []string{"admin", "alice", "mallory"} {
		scope, err := authz.ResolveScope(context.Background(), &auth.PrincipalContext{ID: id}, check, readAll, readOwn)
		if err != nil {
			fmt.Println(id, "denied:", err)
			continue
		}
		fmt.Println(id, "scope:", scope)
	}
	// Output:
	// admin scope: all
	// alice scope: own
	// mallory denied: forbidden
}

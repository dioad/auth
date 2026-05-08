package authz_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth"
	"github.com/dioad/auth/authz"
)

// testMetadata returns a minimal PolicyMetadata for tests.
func testMetadata() authz.PolicyMetadata {
	return authz.PolicyMetadata{
		RoleCapabilities: map[authz.Role][]authz.Capability{
			"publisher": {
				authz.Permission("tunnel", "write"),
				authz.Permission("tunnel", "delete"),
				authz.Permission("endpoint", "write"),
			},
			"reader": {
				authz.Permission("tunnel", "read"),
				authz.Permission("endpoint", "search"),
			},
			"admin": {
				authz.Permission("tunnel", "any"),
				authz.Permission("endpoint", "any"),
				authz.FeatureCapability("custom-domain"),
			},
		},
		RoleAliases: map[string]authz.Role{
			"external.publisher": "publisher",
			"external.reader":    "reader",
			"connect-admin":      "admin",
		},
	}
}

func principal(id string, roles ...string) *auth.PrincipalContext {
	return &auth.PrincipalContext{ID: id, Roles: roles}
}

// ─── Capability constructors ─────────────────────────────────────────────────

func TestCapability_Permission(t *testing.T) {
	cap := authz.Permission("tunnel", "write")
	assert.Equal(t, authz.Capability("tunnel:write"), cap)
}

func TestCapability_FeatureCapability(t *testing.T) {
	cap := authz.FeatureCapability("custom-domain")
	assert.Equal(t, authz.Capability("feature:custom-domain"), cap)
}

// ─── PrivilegeSet ─────────────────────────────────────────────────────────────

func TestPrivilegeSet_Has(t *testing.T) {
	ps := authz.NewPrivilegeSet(authz.Permission("tunnel", "write"))
	assert.True(t, ps.Has(authz.Permission("tunnel", "write")))
	assert.False(t, ps.Has(authz.Permission("tunnel", "delete")))
}

func TestPrivilegeSet_Grant(t *testing.T) {
	ps := authz.NewPrivilegeSet()
	ps.Grant(authz.Permission("tunnel", "read"))
	assert.True(t, ps.Has(authz.Permission("tunnel", "read")))
}

func TestPrivilegeSet_Union_IsOR(t *testing.T) {
	a := authz.NewPrivilegeSet(authz.Permission("tunnel", "write"))
	b := authz.NewPrivilegeSet(authz.Permission("endpoint", "write"))

	result := a.Union(b)
	assert.True(t, result.Has(authz.Permission("tunnel", "write")))
	assert.True(t, result.Has(authz.Permission("endpoint", "write")))
}

func TestPrivilegeSet_Union_DoesNotMutateInputs(t *testing.T) {
	a := authz.NewPrivilegeSet(authz.Permission("tunnel", "write"))
	b := authz.NewPrivilegeSet(authz.Permission("endpoint", "write"))
	_ = a.Union(b)

	assert.False(t, a.Has(authz.Permission("endpoint", "write")), "a must not be mutated by Union")
	assert.False(t, b.Has(authz.Permission("tunnel", "write")), "b must not be mutated by Union")
}

func TestPrivilegeSet_NilSafe(t *testing.T) {
	var ps *authz.PrivilegeSet
	assert.False(t, ps.Has(authz.Permission("tunnel", "write")))
}

// ─── AllowAllAuthorizer ───────────────────────────────────────────────────────

func TestAllowAllAuthorizer_AlwaysGrants(t *testing.T) {
	a := authz.NewAllowAllAuthorizer(testMetadata())

	d, err := a.Can(context.Background(), principal("user", "unknown-role"),
		authz.Permission("tunnel", "write"))
	require.NoError(t, err)
	require.NotNil(t, d)
	assert.True(t, d.Allowed)
	assert.Equal(t, authz.ReasonAllowAll, d.Reason)
}

func TestAllowAllAuthorizer_GrantsNilPrincipal(t *testing.T) {
	// AllowAll bypasses all checks including nil principal.
	a := authz.NewAllowAllAuthorizer(authz.PolicyMetadata{})
	d, err := a.Can(context.Background(), nil, authz.Permission("tunnel", "write"))
	require.NoError(t, err)
	assert.True(t, d.Allowed)
}

func TestAllowAllAuthorizer_Privileges_ReturnsAllowAll(t *testing.T) {
	a := authz.NewAllowAllAuthorizer(authz.PolicyMetadata{})
	privs, err := a.Privileges(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, privs)
	assert.True(t, privs.Has(authz.FeatureCapability("anything")))
	assert.True(t, privs.Has(authz.Permission("any", "action")))
}

// ─── RoleAuthorizer ───────────────────────────────────────────────────────────

func TestRoleAuthorizer_GrantsAliasedRole(t *testing.T) {
	a := authz.NewRoleAuthorizer(testMetadata())

	d, err := a.Can(context.Background(), principal("p1", "external.publisher"),
		authz.Permission("tunnel", "write"))
	require.NoError(t, err)
	require.NotNil(t, d)
	assert.True(t, d.Allowed)
}

func TestRoleAuthorizer_DeniesUnmappedRole(t *testing.T) {
	a := authz.NewRoleAuthorizer(testMetadata())

	// "unknown-role" is not in RoleAliases — must be rejected.
	d, err := a.Can(context.Background(), principal("p1", "unknown-role"),
		authz.Permission("tunnel", "write"))
	require.ErrorIs(t, err, authz.ErrForbidden)
	require.NotNil(t, d)
	assert.False(t, d.Allowed)
	assert.Equal(t, authz.ReasonDeniedNoRoles, d.Reason)
}

func TestRoleAuthorizer_DeniesNilPrincipal(t *testing.T) {
	a := authz.NewRoleAuthorizer(testMetadata())

	d, err := a.Can(context.Background(), nil, authz.Permission("tunnel", "write"))
	require.ErrorIs(t, err, authz.ErrUnauthorized)
	require.NotNil(t, d)
	assert.False(t, d.Allowed)
	assert.Equal(t, authz.ReasonDeniedNilPrincipal, d.Reason)
}

func TestRoleAuthorizer_DeniesInsufficientRole(t *testing.T) {
	a := authz.NewRoleAuthorizer(testMetadata())

	// reader role does not have tunnel:write.
	d, err := a.Can(context.Background(), principal("p1", "external.reader"),
		authz.Permission("tunnel", "write"))
	require.ErrorIs(t, err, authz.ErrForbidden)
	require.NotNil(t, d)
	assert.False(t, d.Allowed)
	assert.Equal(t, authz.ReasonDeniedNoPermission, d.Reason)
}

// TestRoleAuthorizer_UnmappedExternalRoleIsRejected verifies that a token
// carrying an internal role name directly (e.g. "admin") is NOT granted access
// unless it appears in RoleAliases. This guards against role injection.
func TestRoleAuthorizer_UnmappedExternalRoleIsRejected(t *testing.T) {
	a := authz.NewRoleAuthorizer(testMetadata())

	// "admin" is an internal role constant but NOT in RoleAliases. A token
	// carrying the raw string "admin" must not gain admin privileges.
	d, err := a.Can(context.Background(), principal("attacker", "admin"),
		authz.Permission("tunnel", "write"))
	require.ErrorIs(t, err, authz.ErrForbidden)
	assert.False(t, d.Allowed, "raw internal role name must not grant access without alias")
}

func TestRoleAuthorizer_UnionsMultipleRoles(t *testing.T) {
	a := authz.NewRoleAuthorizer(testMetadata())

	// Principal has both publisher and reader roles.
	pc := principal("p1", "external.publisher", "external.reader")

	for _, cap := range []authz.Capability{
		authz.Permission("tunnel", "write"),   // publisher only
		authz.Permission("tunnel", "read"),    // reader only
		authz.Permission("endpoint", "write"), // publisher only
	} {
		d, err := a.Can(context.Background(), pc, cap)
		require.NoError(t, err, "expected allow for %s", cap)
		assert.True(t, d.Allowed, "expected allow for %s", cap)
	}
}

func TestRoleAuthorizer_Privileges_ReturnsCapabilitySet(t *testing.T) {
	a := authz.NewRoleAuthorizer(testMetadata())
	privs, err := a.Privileges(context.Background(), principal("p1", "external.reader"))
	require.NoError(t, err)
	require.NotNil(t, privs)
	assert.True(t, privs.Has(authz.Permission("tunnel", "read")))
	assert.False(t, privs.Has(authz.Permission("tunnel", "write")))
}

func TestRoleAuthorizer_Privileges_ReturnsNilForUnknownPrincipal(t *testing.T) {
	a := authz.NewRoleAuthorizer(testMetadata())
	privs, err := a.Privileges(context.Background(), principal("p1", "no-match"))
	require.NoError(t, err)
	assert.Nil(t, privs)
}

// ─── CasbinAuthorizer ─────────────────────────────────────────────────────────

func TestCasbinAuthorizer_GrantsAliasedRole(t *testing.T) {
	a, err := authz.NewCasbinAuthorizer(testMetadata())
	require.NoError(t, err)

	d, err := a.Can(context.Background(), principal("p1", "external.publisher"),
		authz.Permission("tunnel", "write"))
	require.NoError(t, err)
	require.NotNil(t, d)
	assert.True(t, d.Allowed)
	assert.Equal(t, authz.ReasonGranted, d.Reason)
	assert.NotEmpty(t, d.GrantedBy, "GrantedBy should identify the granting role")
}

func TestCasbinAuthorizer_DeniesNilPrincipal(t *testing.T) {
	a, err := authz.NewCasbinAuthorizer(testMetadata())
	require.NoError(t, err)

	d, err := a.Can(context.Background(), nil, authz.Permission("tunnel", "write"))
	require.ErrorIs(t, err, authz.ErrUnauthorized)
	assert.Equal(t, authz.ReasonDeniedNilPrincipal, d.Reason)
}

func TestCasbinAuthorizer_DeniesUnmappedRole(t *testing.T) {
	a, err := authz.NewCasbinAuthorizer(testMetadata())
	require.NoError(t, err)

	d, err := a.Can(context.Background(), principal("p1", "admin"),
		authz.Permission("tunnel", "write"))
	require.ErrorIs(t, err, authz.ErrForbidden)
	assert.False(t, d.Allowed, "raw 'admin' must not grant access without alias")
	assert.Equal(t, authz.ReasonDeniedNoRoles, d.Reason)
}

func TestCasbinAuthorizer_AnyWildcardGrantsAllActions(t *testing.T) {
	a, err := authz.NewCasbinAuthorizer(testMetadata())
	require.NoError(t, err)

	// "connect-admin" → "admin" which has tunnel:any → all tunnel actions.
	pc := principal("admin-user", "connect-admin")
	for _, action := range []string{"read", "write", "delete", "search"} {
		d, err := a.Can(context.Background(), pc, authz.Permission("tunnel", action))
		require.NoError(t, err, "expected allow for tunnel:%s", action)
		assert.True(t, d.Allowed, "expected allow for tunnel:%s", action)
	}
}

func TestCasbinAuthorizer_DeniesRoleWithoutCapability(t *testing.T) {
	a, err := authz.NewCasbinAuthorizer(testMetadata())
	require.NoError(t, err)

	// reader does not have tunnel:write
	d, err := a.Can(context.Background(), principal("p1", "external.reader"),
		authz.Permission("tunnel", "write"))
	require.ErrorIs(t, err, authz.ErrForbidden)
	assert.False(t, d.Allowed)
	assert.Equal(t, authz.ReasonDeniedNoPermission, d.Reason)
}

func TestCasbinAuthorizer_FeatureCapability(t *testing.T) {
	a, err := authz.NewCasbinAuthorizer(testMetadata())
	require.NoError(t, err)

	// admin has feature:custom-domain
	d, err := a.Can(context.Background(), principal("p1", "connect-admin"),
		authz.FeatureCapability("custom-domain"))
	require.NoError(t, err)
	assert.True(t, d.Allowed)
}

func TestCasbinAuthorizer_ErrForbiddenSentinel(t *testing.T) {
	a, err := authz.NewCasbinAuthorizer(testMetadata())
	require.NoError(t, err)

	_, err = a.Can(context.Background(), principal("p1", "external.reader"),
		authz.Permission("tunnel", "write"))

	// Must be inspectable with errors.Is — not just equality.
	assert.True(t, errors.Is(err, authz.ErrForbidden))
}

func TestCasbinAuthorizer_MissingColonReturnsError(t *testing.T) {
	// A capability without ':' is a programming error; CasbinAuthorizer
	// should return an infrastructure error (nil Decision).
	meta := authz.PolicyMetadata{
		RoleCapabilities: map[authz.Role][]authz.Capability{
			"r": {"no-colon-capability"},
		},
		RoleAliases: map[string]authz.Role{"ext.r": "r"},
	}
	_, err := authz.NewCasbinAuthorizer(meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing ':' separator")
}

// ─── MapAuthorizer ────────────────────────────────────────────────────────────

func TestMapAuthorizer_GrantsKnownPrincipal(t *testing.T) {
	ps := authz.NewPrivilegeSet(authz.Permission("tunnel", "write"))
	a := authz.NewMapAuthorizer(map[string]*authz.PrivilegeSet{"p1": ps}, authz.PolicyMetadata{})

	d, err := a.Can(context.Background(), principal("p1"), authz.Permission("tunnel", "write"))
	require.NoError(t, err)
	assert.True(t, d.Allowed)
}

func TestMapAuthorizer_DeniesUnknownPrincipal(t *testing.T) {
	a := authz.NewMapAuthorizer(map[string]*authz.PrivilegeSet{}, authz.PolicyMetadata{})

	d, err := a.Can(context.Background(), principal("unknown"), authz.Permission("tunnel", "write"))
	require.ErrorIs(t, err, authz.ErrForbidden)
	assert.False(t, d.Allowed)
}

func TestMapAuthorizer_DeniesNilPrincipal(t *testing.T) {
	a := authz.NewMapAuthorizer(map[string]*authz.PrivilegeSet{}, authz.PolicyMetadata{})

	d, err := a.Can(context.Background(), nil, authz.Permission("tunnel", "write"))
	require.ErrorIs(t, err, authz.ErrUnauthorized)
	assert.Equal(t, authz.ReasonDeniedNilPrincipal, d.Reason)
}

// ─── MultiAuthorizer ──────────────────────────────────────────────────────────

func TestMultiAuthorizer_FirstNonNilWins(t *testing.T) {
	// Backend A: knows p1 only
	psA := authz.NewPrivilegeSet(authz.Permission("tunnel", "write"))
	mapA := authz.NewMapAuthorizer(map[string]*authz.PrivilegeSet{"p1": psA}, authz.PolicyMetadata{})

	// Backend B: knows p2 only
	psB := authz.NewPrivilegeSet(authz.Permission("endpoint", "write"))
	mapB := authz.NewMapAuthorizer(map[string]*authz.PrivilegeSet{"p2": psB}, authz.PolicyMetadata{})

	m := authz.NewMultiAuthorizer(mapA, mapB)

	d1, err := m.Can(context.Background(), principal("p1"), authz.Permission("tunnel", "write"))
	require.NoError(t, err)
	assert.True(t, d1.Allowed)

	d2, err := m.Can(context.Background(), principal("p2"), authz.Permission("endpoint", "write"))
	require.NoError(t, err)
	assert.True(t, d2.Allowed)
}

func TestMultiAuthorizer_DoesNotFallThroughOnAllow(t *testing.T) {
	// Backend A grants tunnel:write
	psA := authz.NewPrivilegeSet(authz.Permission("tunnel", "write"))
	mapA := authz.NewMapAuthorizer(map[string]*authz.PrivilegeSet{"p1": psA}, authz.PolicyMetadata{})

	// Backend B also knows p1 but only grants endpoint:write
	// If MultiAuthorizer fell through, p1 would not get endpoint:write from A.
	// The correct behaviour: once A returns a Privilege, we stop.
	psB := authz.NewPrivilegeSet(authz.Permission("endpoint", "write"))
	mapB := authz.NewMapAuthorizer(map[string]*authz.PrivilegeSet{"p1": psB}, authz.PolicyMetadata{})

	m := authz.NewMultiAuthorizer(mapA, mapB)

	// p1 is found in A; endpoint:write from B should NOT be visible.
	d, err := m.Can(context.Background(), principal("p1"), authz.Permission("endpoint", "write"))
	require.ErrorIs(t, err, authz.ErrForbidden, "must not fall through to backend B")
	assert.False(t, d.Allowed)
}

func TestMultiAuthorizer_DeniesWhenNoneMatch(t *testing.T) {
	m := authz.NewMultiAuthorizer(
		authz.NewMapAuthorizer(map[string]*authz.PrivilegeSet{}, authz.PolicyMetadata{}),
	)
	d, err := m.Can(context.Background(), principal("nobody"), authz.Permission("tunnel", "write"))
	require.ErrorIs(t, err, authz.ErrForbidden)
	assert.False(t, d.Allowed)
}

// ─── AuthorizerConfig ─────────────────────────────────────────────────────────

func TestAuthorizerConfig_ToMetadata(t *testing.T) {
	cfg := authz.AuthorizerConfig{
		RoleCapabilities: []authz.RoleCapabilityConfig{
			{Role: "publisher", Capabilities: []string{"tunnel:write", "tunnel:delete"}},
		},
		RoleAliases: map[string]string{"external.publisher": "publisher"},
	}
	meta := cfg.ToMetadata()

	require.Len(t, meta.RoleCapabilities[authz.Role("publisher")], 2)
	assert.Equal(t, authz.Role("publisher"), meta.RoleAliases["external.publisher"])
}

// ─── Security: ErrForbidden vs infrastructure errors ─────────────────────────

func TestDecision_NilOnInfrastructureError(t *testing.T) {
	// CasbinAuthorizer.Can with a malformed capability (no colon) returns a nil
	// Decision — it is not a policy decision.
	meta := authz.PolicyMetadata{
		RoleCapabilities: map[authz.Role][]authz.Capability{
			"r": {authz.Permission("tunnel", "write")},
		},
		RoleAliases: map[string]authz.Role{"ext.r": "r"},
	}
	a, err := authz.NewCasbinAuthorizer(meta)
	require.NoError(t, err)

	// Pass a Capability without ':' directly (bypassing constructors).
	d, err := a.Can(context.Background(), principal("p1", "ext.r"), authz.Capability("no-colon"))
	require.Error(t, err)
	assert.False(t, errors.Is(err, authz.ErrForbidden), "infrastructure error must not be ErrForbidden")
	assert.Nil(t, d, "Decision must be nil for infrastructure errors")
}

// ─── Wildcard privilege tests ────────────────────────────────────────────────

func TestWildcardPrivilege_Has_ExactMatch(t *testing.T) {
	ps := authz.NewPrivilegeSet(authz.Permission("tunnel", "write"))
	p := authz.NewWildcardPrivilege(ps)
	assert.True(t, p.Has(authz.Permission("tunnel", "write")), "exact match must be granted")
	assert.False(t, p.Has(authz.Permission("tunnel", "read")), "ungranted capability must be denied")
}

func TestWildcardPrivilege_Has_WildcardGrantsAction(t *testing.T) {
	ps := authz.NewPrivilegeSet(authz.Permission("tunnel", "any"))
	p := authz.NewWildcardPrivilege(ps)
	assert.True(t, p.Has(authz.Permission("tunnel", "write")), "tunnel:any must grant tunnel:write")
	assert.True(t, p.Has(authz.Permission("tunnel", "read")), "tunnel:any must grant tunnel:read")
	assert.True(t, p.Has(authz.Permission("tunnel", "delete")), "tunnel:any must grant tunnel:delete")
	assert.False(t, p.Has(authz.Permission("endpoint", "write")), "tunnel:any must not grant endpoint:write")
}

func TestWildcardPrivilege_Has_FeatureWildcard(t *testing.T) {
	ps := authz.NewPrivilegeSet(authz.FeatureCapability("any"))
	p := authz.NewWildcardPrivilege(ps)
	assert.True(t, p.Has(authz.FeatureCapability("custom-domain")), "feature:any must grant feature:custom-domain")
}

func TestWildcardPrivilege_Has_NilSet(t *testing.T) {
	p := authz.NewWildcardPrivilege(nil)
	assert.False(t, p.Has(authz.Permission("tunnel", "write")), "nil set must deny all")
}

func TestCasbinAuthorizer_Privileges_ConsistentWithCan(t *testing.T) {
	// admin has tunnel:any; Can("tunnel:write") must agree with Privileges().Has("tunnel:write")
	meta := testMetadata()
	a, err := authz.NewCasbinAuthorizer(meta)
	require.NoError(t, err)

	ctx := context.Background()
	p := principal("admin1", "connect-admin") // maps to "admin" via alias

	d, canErr := a.Can(ctx, p, authz.Permission("tunnel", "write"))
	require.NoError(t, canErr)
	require.NotNil(t, d)
	assert.True(t, d.Allowed)

	privs, privsErr := a.Privileges(ctx, p)
	require.NoError(t, privsErr)
	require.NotNil(t, privs)
	assert.True(t, privs.Has(authz.Permission("tunnel", "write")),
		"Privileges().Has() must agree with Can() for wildcard capabilities")
}

func TestRoleAuthorizer_Privileges_ConsistentWithCan(t *testing.T) {
	meta := testMetadata()
	a := authz.NewRoleAuthorizer(meta)

	ctx := context.Background()
	p := principal("admin2", "connect-admin")

	d, canErr := a.Can(ctx, p, authz.Permission("tunnel", "read"))
	require.NoError(t, canErr)
	require.NotNil(t, d)
	assert.True(t, d.Allowed)

	privs, privsErr := a.Privileges(ctx, p)
	require.NoError(t, privsErr)
	require.NotNil(t, privs)
	assert.True(t, privs.Has(authz.Permission("tunnel", "read")),
		"Privileges().Has() must agree with Can() for wildcard capabilities")
}

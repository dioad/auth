package mapper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapRoles_ExactMatch(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"repository": "org/repo", "environment": "production"}, Role: "registry.publisher"},
	})

	got := m.MapRoles(map[string]any{"repository": "org/repo", "environment": "production"})
	assert.Equal(t, []string{"registry.publisher"}, got)
}

func TestMapRoles_PartialMatch(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"repository": "org/repo", "environment": "production"}, Role: "registry.publisher"},
	})

	got := m.MapRoles(map[string]any{"repository": "org/repo"}) // missing environment
	assert.Empty(t, got)
}

func TestMapRoles_Wildcard(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"app_name": "*"}, Role: "registry.publisher"},
	})

	got := m.MapRoles(map[string]any{"app_name": "connect-server-prod"})
	assert.Equal(t, []string{"registry.publisher"}, got)

	// empty value should not match wildcard
	got = m.MapRoles(map[string]any{"app_name": ""})
	assert.Empty(t, got)
}

func TestMapRoles_MultipleRules(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"app_name": "connect-server"}, Role: "registry.publisher"},
		{Claims: map[string]string{"app_name": "connect-server"}, Role: "registry.router-reader"},
	})

	got := m.MapRoles(map[string]any{"app_name": "connect-server"})
	assert.Len(t, got, 2)
}

func TestMapRoles_NoMatch(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"app_name": "connect-server"}, Role: "registry.publisher"},
	})

	got := m.MapRoles(map[string]any{"app_name": "other-app"})
	assert.Empty(t, got)
}

func TestNew_EmptyMappings(t *testing.T) {
	assert.Nil(t, New(nil))
	assert.Nil(t, New([]ClaimRoleMapping{}))
}

func TestMapRoles_MissingClaim(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"missing_key": "value"}, Role: "registry.publisher"},
	})

	got := m.MapRoles(map[string]any{"other_key": "value"})
	assert.Empty(t, got)
}

func TestMapRoles_ArrayClaimContainsMatch(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"groups": "plan:pro"}, Role: "pro-tier"},
	})

	// []any is what encoding/json produces for a JSON array claim decoded
	// into map[string]any, e.g. a Keycloak groups/roles list.
	got := m.MapRoles(map[string]any{"groups": []any{"plan:pro", "other-group"}})
	assert.Equal(t, []string{"pro-tier"}, got)

	got = m.MapRoles(map[string]any{"groups": []any{"plan:free"}})
	assert.Empty(t, got)
}

func TestMapRoles_ArrayClaimStringSlice(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"groups": "plan:pro"}, Role: "pro-tier"},
	})

	got := m.MapRoles(map[string]any{"groups": []string{"plan:pro"}})
	assert.Equal(t, []string{"pro-tier"}, got)
}

func TestMapRoles_ArrayClaimWildcard(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"groups": "*"}, Role: "any-group-member"},
	})

	got := m.MapRoles(map[string]any{"groups": []any{"plan:free"}})
	assert.Equal(t, []string{"any-group-member"}, got)

	// empty array should not match wildcard, mirroring the empty-string case
	got = m.MapRoles(map[string]any{"groups": []any{}})
	assert.Empty(t, got)
}

func TestMapRoles_ArrayClaimNonStringElementsIgnored(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"groups": "plan:pro"}, Role: "pro-tier"},
	})

	// non-string elements are skipped rather than causing a panic or a false match
	got := m.MapRoles(map[string]any{"groups": []any{1, true, "plan:pro"}})
	assert.Equal(t, []string{"pro-tier"}, got)
}

func TestMapRoles_UnsupportedClaimType(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"groups": "plan:pro"}, Role: "pro-tier"},
	})

	got := m.MapRoles(map[string]any{"groups": 42})
	assert.Empty(t, got)
}

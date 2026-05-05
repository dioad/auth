package mapper

import (
	"testing"
)

func TestMapRoles_ExactMatch(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"repository": "org/repo", "environment": "production"}, Role: "registry.publisher"},
	})

	got := m.MapRoles(map[string]any{"repository": "org/repo", "environment": "production"})
	if len(got) != 1 || got[0] != "registry.publisher" {
		t.Errorf("expected [registry.publisher], got %v", got)
	}
}

func TestMapRoles_PartialMatch(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"repository": "org/repo", "environment": "production"}, Role: "registry.publisher"},
	})

	got := m.MapRoles(map[string]any{"repository": "org/repo"}) // missing environment
	if len(got) != 0 {
		t.Errorf("expected no roles, got %v", got)
	}
}

func TestMapRoles_Wildcard(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"app_name": "*"}, Role: "registry.publisher"},
	})

	got := m.MapRoles(map[string]any{"app_name": "connect-server-prod"})
	if len(got) != 1 || got[0] != "registry.publisher" {
		t.Errorf("expected [registry.publisher], got %v", got)
	}

	// empty value should not match wildcard
	got = m.MapRoles(map[string]any{"app_name": ""})
	if len(got) != 0 {
		t.Errorf("expected no roles for empty value, got %v", got)
	}
}

func TestMapRoles_MultipleRules(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"app_name": "connect-server"}, Role: "registry.publisher"},
		{Claims: map[string]string{"app_name": "connect-server"}, Role: "registry.router-reader"},
	})

	got := m.MapRoles(map[string]any{"app_name": "connect-server"})
	if len(got) != 2 {
		t.Errorf("expected 2 roles, got %v", got)
	}
}

func TestMapRoles_NoMatch(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"app_name": "connect-server"}, Role: "registry.publisher"},
	})

	got := m.MapRoles(map[string]any{"app_name": "other-app"})
	if len(got) != 0 {
		t.Errorf("expected no roles, got %v", got)
	}
}

func TestNew_EmptyMappings(t *testing.T) {
	m := New(nil)
	if m != nil {
		t.Errorf("expected nil mapper for empty mappings")
	}

	m = New([]ClaimRoleMapping{})
	if m != nil {
		t.Errorf("expected nil mapper for empty slice")
	}
}

func TestMapRoles_MissingClaim(t *testing.T) {
	m := New([]ClaimRoleMapping{
		{Claims: map[string]string{"missing_key": "value"}, Role: "registry.publisher"},
	})

	got := m.MapRoles(map[string]any{"other_key": "value"})
	if len(got) != 0 {
		t.Errorf("expected no roles when claim key absent, got %v", got)
	}
}

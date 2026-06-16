package claimrolemapping

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dioad/auth/authz"
	"github.com/rs/zerolog"
)

// testPolicy returns a synthetic PolicyMetadata for use in tests. It is
// intentionally generic — no application-specific role names.
func testPolicy() authz.PolicyMetadata {
	return authz.PolicyMetadata{
		RoleCapabilities: map[authz.Role][]authz.Capability{
			"role.reader":    nil,
			"role.publisher": nil,
			"admin":          nil,
			"role-a":         nil,
			"role-b":         nil,
		},
		RoleAliases: map[string]authz.Role{
			"connect-admin": "admin",
		},
	}
}

func TestResolveClaimRoleMappingRoles_CanonicalRolesUnchanged(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Role: "role.reader", Claims: map[string]string{"aws_account": "123"}},
		{Role: "role.publisher", Claims: map[string]string{"aud": "my-service"}},
	}
	resolved := resolveClaimRoleMappingRoles(mappings, testPolicy(), "test", zerolog.Nop())
	if len(resolved) != len(mappings) {
		t.Fatalf("len(resolved) = %d, want %d", len(resolved), len(mappings))
	}
	if resolved[0].Role != "role.reader" {
		t.Errorf("resolved[0].Role = %q, want %q", resolved[0].Role, "role.reader")
	}
	if resolved[1].Role != "role.publisher" {
		t.Errorf("resolved[1].Role = %q, want %q", resolved[1].Role, "role.publisher")
	}
}

func TestResolveClaimRoleMappingRoles_AliasResolvesToCanonical(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Role: "connect-admin", Claims: map[string]string{"org": "my-org"}},
	}
	resolved := resolveClaimRoleMappingRoles(mappings, testPolicy(), "test", zerolog.Nop())
	if resolved[0].Role != "admin" {
		t.Errorf("resolved[0].Role = %q, want %q (alias must resolve to canonical)", resolved[0].Role, "admin")
	}
}

func TestResolveClaimRoleMappingRoles_UnknownRoleLogsWarning(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	mappings := []ClaimRoleMappingConfig{
		{Role: "unknown-role", Claims: map[string]string{"x": "y"}},
	}
	resolveClaimRoleMappingRoles(mappings, testPolicy(), "test", logger)

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v", err)
	}
	if entry["level"] != "warn" {
		t.Errorf("log level = %q, want %q", entry["level"], "warn")
	}
	if entry["role"] != "unknown-role" {
		t.Errorf("log role = %q, want %q", entry["role"], "unknown-role")
	}
}

func TestResolveClaimRoleMappingRoles_DoesNotMutateInput(t *testing.T) {
	original := []ClaimRoleMappingConfig{
		{Role: "connect-admin", Claims: map[string]string{"org": "my-org"}},
	}
	originalRole := original[0].Role
	resolveClaimRoleMappingRoles(original, testPolicy(), "test", zerolog.Nop())
	if original[0].Role != originalRole {
		t.Errorf("input slice was mutated: original[0].Role = %q, want %q", original[0].Role, originalRole)
	}
}

func TestResolveClaimRoleMappingRoles_DeepCopiesClaimsMap(t *testing.T) {
	original := []ClaimRoleMappingConfig{
		{Role: "role.reader", Claims: map[string]string{"org": "my-org"}},
	}
	resolved := resolveClaimRoleMappingRoles(original, testPolicy(), "test", zerolog.Nop())
	// Mutating the resolved Claims map must not affect the original.
	resolved[0].Claims["injected"] = "value"
	if _, ok := original[0].Claims["injected"]; ok {
		t.Error("mutating resolved Claims map affected the original input — shallow copy detected")
	}
}

func TestResolveClaimRoleMappingRoles_EmptyClaimsLogsWarning(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	mappings := []ClaimRoleMappingConfig{
		{Role: "role.reader", Claims: map[string]string{}},
	}
	resolveClaimRoleMappingRoles(mappings, testPolicy(), "test", logger)

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v", err)
	}
	if entry["level"] != "warn" {
		t.Errorf("log level = %q, want %q", entry["level"], "warn")
	}
	msg, _ := entry["message"].(string)
	if !strings.Contains(msg, "no claim predicates") && !strings.Contains(msg, "every principal") {
		t.Errorf("expected warning about empty claims, got message: %q", msg)
	}
}

func TestBuildMapper_ReturnsDebugMapperWhenAnyRuleHasDebug(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Source: SourceFlyio, Role: "role-a", Claims: map[string]string{"k": "v"}, Debug: false},
		{Source: SourceFlyio, Role: "role-b", Claims: map[string]string{"k": "v"}, Debug: true},
	}
	m := buildMapper(mappings, testPolicy(), SourceFlyio, zerolog.Nop())
	if _, ok := m.(*debugAwareMapper); !ok {
		t.Errorf("expected *debugAwareMapper when any rule has Debug=true, got %T", m)
	}
}

func TestBuildMapper_ReturnsNilForEmptyMappings(t *testing.T) {
	m := buildMapper(nil, testPolicy(), SourceFlyio, zerolog.Nop())
	if m != nil {
		t.Errorf("expected nil mapper for empty mappings, got %T", m)
	}
}

func TestBuildMapper_ReturnsStandardMapperWithNoDebugRules(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Source: SourceFlyio, Role: "role-a", Claims: map[string]string{"k": "v"}, Debug: false},
	}
	m := buildMapper(mappings, testPolicy(), SourceFlyio, zerolog.Nop())
	if _, ok := m.(*debugAwareMapper); ok {
		t.Errorf("expected standard mapper when no rule has Debug=true, got *debugAwareMapper")
	}
	if m == nil {
		t.Error("expected non-nil mapper for non-empty mappings with no debug rules")
	}
}

func TestBuildPrincipalExtractor_AllowUnauthenticated(t *testing.T) {
	config := ExtractorConfig{AllowUnauthenticated: true}
	extractor := BuildPrincipalExtractor(config, testPolicy(), zerolog.Nop())
	if extractor == nil {
		t.Fatal("expected non-nil extractor in unauthenticated mode")
	}
}

func TestBuildPrincipalExtractor_Authenticated(t *testing.T) {
	config := ExtractorConfig{
		AllowUnauthenticated: false,
		ClaimRoleMappings: []ClaimRoleMappingConfig{
			{Source: SourceFlyio, Role: "role.publisher", Claims: map[string]string{"org_name": "my-org"}},
		},
	}
	extractor := BuildPrincipalExtractor(config, testPolicy(), zerolog.Nop())
	if extractor == nil {
		t.Fatal("expected non-nil extractor in authenticated mode")
	}
}

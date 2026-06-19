package claimrolemapping

import (
	"testing"
)

func TestValidateRoleMappings_NoWarningsWhenAllKnown(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Role: "admin"},
		{Role: "viewer"},
	}
	warnings := ValidateRoleMappings(mappings, []string{"admin", "viewer", "editor"})
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
}

func TestValidateRoleMappings_WarnsForUnknownRole(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Role: "admin"},
		{Role: "superadmin"},
	}
	warnings := ValidateRoleMappings(mappings, []string{"admin", "viewer"})
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if warnings[0] == "" {
		t.Error("expected non-empty warning message")
	}
}

func TestValidateRoleMappings_WarnsForEachUnknownRole(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Role: "unknown1"},
		{Role: "known"},
		{Role: "unknown2"},
	}
	warnings := ValidateRoleMappings(mappings, []string{"known"})
	if len(warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestValidateRoleMappings_EmptyMappings(t *testing.T) {
	warnings := ValidateRoleMappings(nil, []string{"admin"})
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for empty mappings, got %v", warnings)
	}
}

func TestValidateRoleMappings_EmptyKnownRoles(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Role: "admin"},
	}
	warnings := ValidateRoleMappings(mappings, nil)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
}

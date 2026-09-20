package claimrolemapping

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRoleMappings_NoWarningsWhenAllKnown(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Role: "admin"},
		{Role: "viewer"},
	}
	warnings := ValidateRoleMappings(mappings, []string{"admin", "viewer", "editor"})
	assert.Empty(t, warnings)
}

func TestValidateRoleMappings_WarnsForUnknownRole(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Role: "admin"},
		{Role: "superadmin"},
	}
	warnings := ValidateRoleMappings(mappings, []string{"admin", "viewer"})
	require.Len(t, warnings, 1)
	assert.NotEmpty(t, warnings[0], "expected non-empty warning message")
}

func TestValidateRoleMappings_WarnsForEachUnknownRole(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Role: "unknown1"},
		{Role: "known"},
		{Role: "unknown2"},
	}
	warnings := ValidateRoleMappings(mappings, []string{"known"})
	require.Len(t, warnings, 2)
}

func TestValidateRoleMappings_EmptyMappings(t *testing.T) {
	warnings := ValidateRoleMappings(nil, []string{"admin"})
	assert.Empty(t, warnings, "expected no warnings for empty mappings")
}

func TestValidateRoleMappings_EmptyKnownRoles(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Role: "admin"},
	}
	warnings := ValidateRoleMappings(mappings, nil)
	require.Len(t, warnings, 1)
}

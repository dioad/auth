package claimrolemapping

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveClaimRoleMappingRoles_CanonicalRolesUnchanged(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Role: "role.reader", Claims: map[string]string{"aws_account": "123"}},
		{Role: "role.publisher", Claims: map[string]string{"aud": "my-service"}},
	}
	resolved := resolveClaimRoleMappingRoles(mappings, "test", zerolog.Nop())
	require.Len(t, resolved, len(mappings))
	assert.Equal(t, "role.reader", resolved[0].Role)
	assert.Equal(t, "role.publisher", resolved[1].Role)
}

func TestResolveClaimRoleMappingRoles_DoesNotMutateInput(t *testing.T) {
	original := []ClaimRoleMappingConfig{
		{Role: "connect-admin", Claims: map[string]string{"org": "my-org"}},
	}
	originalRole := original[0].Role
	resolveClaimRoleMappingRoles(original, "test", zerolog.Nop())
	assert.Equal(t, originalRole, original[0].Role, "input slice was mutated")
}

func TestResolveClaimRoleMappingRoles_DeepCopiesClaimsMap(t *testing.T) {
	original := []ClaimRoleMappingConfig{
		{Role: "role.reader", Claims: map[string]string{"org": "my-org"}},
	}
	resolved := resolveClaimRoleMappingRoles(original, "test", zerolog.Nop())
	// Mutating the resolved Claims map must not affect the original.
	resolved[0].Claims["injected"] = "value"
	assert.NotContains(t, original[0].Claims, "injected", "mutating resolved Claims map affected the original input — shallow copy detected")
}

func TestResolveClaimRoleMappingRoles_EmptyClaimsLogsWarning(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	mappings := []ClaimRoleMappingConfig{
		{Role: "role.reader", Claims: map[string]string{}},
	}
	resolveClaimRoleMappingRoles(mappings, "test", logger)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry), "failed to parse log output")
	assert.Equal(t, "warn", entry["level"])
	msg, _ := entry["message"].(string)
	assert.Truef(t, strings.Contains(msg, "no claim predicates") || strings.Contains(msg, "every principal"),
		"expected warning about empty claims, got message: %q", msg)
}

func TestBuildMapper_ReturnsDebugMapperWhenAnyRuleHasDebug(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Source: SourceFlyio, Role: "role-a", Claims: map[string]string{"k": "v"}, Debug: false},
		{Source: SourceFlyio, Role: "role-b", Claims: map[string]string{"k": "v"}, Debug: true},
	}
	m := buildMapper(mappings, SourceFlyio, zerolog.Nop())
	assert.IsType(t, &debugAwareMapper{}, m)
}

func TestBuildMapper_ReturnsNilForEmptyMappings(t *testing.T) {
	m := buildMapper(nil, SourceFlyio, zerolog.Nop())
	assert.Nil(t, m)
}

func TestBuildMapper_ReturnsStandardMapperWithNoDebugRules(t *testing.T) {
	mappings := []ClaimRoleMappingConfig{
		{Source: SourceFlyio, Role: "role-a", Claims: map[string]string{"k": "v"}, Debug: false},
	}
	m := buildMapper(mappings, SourceFlyio, zerolog.Nop())
	_, isDebugMapper := m.(*debugAwareMapper)
	assert.False(t, isDebugMapper, "expected standard mapper when no rule has Debug=true, got *debugAwareMapper")
	assert.NotNil(t, m, "expected non-nil mapper for non-empty mappings with no debug rules")
}

func TestBuildPrincipalExtractor_AllowUnauthenticated(t *testing.T) {
	config := ExtractorConfig{AllowUnauthenticated: new(true)}
	extractor := BuildPrincipalExtractor(config, zerolog.Nop())
	require.NotNil(t, extractor, "expected non-nil extractor in unauthenticated mode")
}

func TestBuildPrincipalExtractor_Authenticated(t *testing.T) {
	config := ExtractorConfig{
		AllowUnauthenticated: new(false),
		ClaimRoleMappings: []ClaimRoleMappingConfig{
			{Source: SourceFlyio, Role: "role.publisher", Claims: map[string]string{"org_name": "my-org"}},
		},
	}
	extractor := BuildPrincipalExtractor(config, zerolog.Nop())
	require.NotNil(t, extractor, "expected non-nil extractor in authenticated mode")
}

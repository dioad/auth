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

// newTestLogger returns a zerolog.Logger that writes JSON to buf at Debug level.
func newTestLogger(buf *bytes.Buffer) zerolog.Logger {
	return zerolog.New(buf).Level(zerolog.DebugLevel)
}

func TestDebugAwareMapper_MatchedRuleEmitsDebugEvent(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	m := &debugAwareMapper{
		source: SourceFlyio,
		logger: logger,
		mappings: []ClaimRoleMappingConfig{
			{
				Source: SourceFlyio,
				Role:   "role.publisher",
				Claims: map[string]string{
					"org_name": "my-org",
					"app_name": "my-app",
				},
				Debug: true,
			},
		},
	}

	roles := m.MapRoles(map[string]any{
		"org_name": "my-org",
		"app_name": "my-app",
	})

	require.Equal(t, []string{"role.publisher"}, roles)

	output := buf.String()
	assert.Contains(t, output, "rule matched")
	assert.Contains(t, output, "evaluation complete")
}

func TestDebugAwareMapper_UnmatchedRuleLogsFailedClaim(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	m := &debugAwareMapper{
		source: SourceFlyio,
		logger: logger,
		mappings: []ClaimRoleMappingConfig{
			{
				Source: SourceFlyio,
				Role:   "role.publisher",
				Claims: map[string]string{
					"org_name": "my-org",
					"app_name": "my-app",
				},
				Debug: true,
			},
		},
	}

	roles := m.MapRoles(map[string]any{
		"org_name": "other-org",
	})

	require.Empty(t, roles)

	output := buf.String()
	assert.Contains(t, output, "rule did not match")
	assert.Contains(t, output, "failed_claim")
}

func TestDebugAwareMapper_NonDebugRuleOmitsPerRuleEvents(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	// Mix: one non-debug rule and one debug rule.
	m := &debugAwareMapper{
		source: SourceFlyio,
		logger: logger,
		mappings: []ClaimRoleMappingConfig{
			{
				Source: SourceFlyio,
				Role:   "role.reader",
				Claims: map[string]string{"org_name": "my-org"},
				Debug:  false,
			},
			{
				Source: SourceFlyio,
				Role:   "role.debug",
				Claims: map[string]string{"org_name": "other"},
				Debug:  true,
			},
		},
	}

	m.MapRoles(map[string]any{"org_name": "my-org"})

	var overviewMsgs, perRuleRoles []string
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var evt map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &evt), "non-JSON log line: %s", line)
		msg, _ := evt["message"].(string)
		switch msg {
		case "claim-role-mapping: evaluating claims", "claim-role-mapping: evaluation complete":
			overviewMsgs = append(overviewMsgs, msg)
		case "claim-role-mapping: rule matched, role granted", "claim-role-mapping: rule did not match":
			if role, ok := evt["role"].(string); ok {
				perRuleRoles = append(perRuleRoles, role)
			}
		}
	}

	assert.Len(t, overviewMsgs, 2)
	assert.NotContains(t, perRuleRoles, "role.reader", "per-rule event emitted for non-debug rule 'role.reader'")
}

func TestDebugAwareMapper_GrantedRolesAppearsInFinalEvent(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	m := &debugAwareMapper{
		source: SourceJWT,
		logger: logger,
		mappings: []ClaimRoleMappingConfig{
			{Source: SourceJWT, Role: "role-a", Claims: map[string]string{"env": "prod"}, Debug: true},
			{Source: SourceJWT, Role: "role-b", Claims: map[string]string{"team": "*"}, Debug: true},
		},
	}

	roles := m.MapRoles(map[string]any{"env": "prod", "team": "platform"})
	require.Len(t, roles, 2)

	var found bool
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var evt map[string]any
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			continue
		}
		if evt["message"] == "claim-role-mapping: evaluation complete" {
			found = true
			rolesField, ok := evt["roles_granted"].([]any)
			if assert.True(t, ok, "roles_granted field missing or wrong type in: %s", line) {
				assert.Len(t, rolesField, 2, "in: %s", line)
			}
		}
	}
	assert.True(t, found, "evaluation complete event not found in output:\n%s", buf.String())
}

func TestEvalMapping_MissingClaim(t *testing.T) {
	matched, failedClaim, want, got := evalMapping(
		map[string]any{"other": "val"},
		map[string]string{"missing_key": "expected"},
	)
	require.False(t, matched, "expected mismatch for missing claim")
	assert.Equal(t, "missing_key", failedClaim)
	assert.Equal(t, "expected", want)
	assert.Equal(t, "<missing>", got)
}

func TestEvalMapping_TypeMismatch(t *testing.T) {
	matched, failedClaim, _, got := evalMapping(
		map[string]any{"count": 42},
		map[string]string{"count": "42"},
	)
	require.False(t, matched, "expected mismatch for non-string claim value")
	assert.Equal(t, "count", failedClaim)
	assert.True(t, strings.HasPrefix(got, "<type:"), "got = %q, expected <type:...> prefix", got)
}

func TestEvalMapping_WildcardEmptyString(t *testing.T) {
	matched, failedClaim, want, got := evalMapping(
		map[string]any{"app_name": ""},
		map[string]string{"app_name": "*"},
	)
	require.False(t, matched, "expected mismatch for empty wildcard value")
	assert.Equal(t, "app_name", failedClaim)
	assert.Equal(t, "*", want)
	assert.Equal(t, "<empty>", got)
}

func TestEvalMapping_WildcardNonEmptyMatches(t *testing.T) {
	matched, _, _, _ := evalMapping(
		map[string]any{"app_name": "my-app"},
		map[string]string{"app_name": "*"},
	)
	assert.True(t, matched, "expected wildcard to match non-empty string")
}

func TestEvalMapping_ValueMismatch(t *testing.T) {
	matched, failedClaim, want, got := evalMapping(
		map[string]any{"env": "staging"},
		map[string]string{"env": "prod"},
	)
	require.False(t, matched, "expected mismatch for wrong claim value")
	assert.Equal(t, "env", failedClaim)
	assert.Equal(t, "prod", want)
	assert.Equal(t, "staging", got)
}

// TestEvalMapping_ArrayClaimContainsMatch is the regression test for the
// debug-logging path silently reverting to string-only matching: evalMapping
// must accept an array claim (e.g. Keycloak's "groups"/"roles" list, decoded
// as []any) the same way mapper.MatchesValue does, not just a scalar string.
func TestEvalMapping_ArrayClaimContainsMatch(t *testing.T) {
	matched, _, _, _ := evalMapping(
		map[string]any{"groups": []any{"plan:pro", "other-group"}},
		map[string]string{"groups": "plan:pro"},
	)
	assert.True(t, matched, "expected array claim containing want to match")
}

func TestEvalMapping_ArrayClaimNoMatchReportsElements(t *testing.T) {
	matched, failedClaim, want, got := evalMapping(
		map[string]any{"groups": []any{"plan:free"}},
		map[string]string{"groups": "plan:pro"},
	)
	require.False(t, matched, "expected mismatch when array does not contain want")
	assert.Equal(t, "groups", failedClaim)
	assert.Equal(t, "plan:pro", want)
	assert.Equal(t, "[plan:free]", got, "expected the array's contents")
}

func TestEvalMapping_ArrayClaimWildcardMatchesNonEmpty(t *testing.T) {
	matched, _, _, _ := evalMapping(
		map[string]any{"groups": []any{"plan:free"}},
		map[string]string{"groups": "*"},
	)
	assert.True(t, matched, "expected wildcard to match a non-empty array")
}

// TestDebugAwareMapper_ArrayClaimMatchesLikeStandardMapper is the end-to-end
// regression test: a rule keyed on an array claim must grant its role via the
// debug-logging mapper exactly as it would via the standard mapper.Mapper —
// enabling debug on one rule must not change matching behaviour for others.
func TestDebugAwareMapper_ArrayClaimMatchesLikeStandardMapper(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	m := &debugAwareMapper{
		source: SourceOIDC,
		logger: logger,
		mappings: []ClaimRoleMappingConfig{
			{Source: SourceOIDC, Role: "pro-tier", Claims: map[string]string{"groups": "plan:pro"}, Debug: true},
		},
	}

	roles := m.MapRoles(map[string]any{"groups": []any{"plan:pro", "other-group"}})
	require.Equal(t, []string{"pro-tier"}, roles)
}

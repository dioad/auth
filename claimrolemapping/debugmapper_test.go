package claimrolemapping

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
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

	if len(roles) != 1 || roles[0] != "role.publisher" {
		t.Fatalf("expected [role.publisher], got %v", roles)
	}

	output := buf.String()
	if !strings.Contains(output, "rule matched") {
		t.Errorf("expected 'rule matched' in debug output, got:\n%s", output)
	}
	if !strings.Contains(output, "evaluation complete") {
		t.Errorf("expected 'evaluation complete' in debug output, got:\n%s", output)
	}
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

	if len(roles) != 0 {
		t.Fatalf("expected no roles, got %v", roles)
	}

	output := buf.String()
	if !strings.Contains(output, "rule did not match") {
		t.Errorf("expected 'rule did not match' in debug output, got:\n%s", output)
	}
	if !strings.Contains(output, "failed_claim") {
		t.Errorf("expected 'failed_claim' field in debug output, got:\n%s", output)
	}
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
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			t.Fatalf("non-JSON log line: %s", line)
		}
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

	if len(overviewMsgs) != 2 {
		t.Errorf("expected 2 overview events, got %d: %v", len(overviewMsgs), overviewMsgs)
	}
	for _, role := range perRuleRoles {
		if role == "role.reader" {
			t.Errorf("per-rule event emitted for non-debug rule 'role.reader'")
		}
	}
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
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %v", roles)
	}

	var found bool
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var evt map[string]any
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			continue
		}
		if evt["message"] == "claim-role-mapping: evaluation complete" {
			found = true
			rolesField, ok := evt["roles_granted"].([]any)
			if !ok {
				t.Errorf("roles_granted field missing or wrong type in: %s", line)
			}
			if len(rolesField) != 2 {
				t.Errorf("expected 2 roles_granted, got %d in: %s", len(rolesField), line)
			}
		}
	}
	if !found {
		t.Errorf("evaluation complete event not found in output:\n%s", buf.String())
	}
}

func TestEvalMapping_MissingClaim(t *testing.T) {
	matched, failedClaim, want, got := evalMapping(
		map[string]any{"other": "val"},
		map[string]string{"missing_key": "expected"},
	)
	if matched {
		t.Fatal("expected mismatch for missing claim")
	}
	if failedClaim != "missing_key" {
		t.Errorf("failedClaim = %q, want %q", failedClaim, "missing_key")
	}
	if want != "expected" {
		t.Errorf("want = %q, expected %q", want, "expected")
	}
	if got != "<missing>" {
		t.Errorf("got = %q, want %q", got, "<missing>")
	}
}

func TestEvalMapping_TypeMismatch(t *testing.T) {
	matched, failedClaim, _, got := evalMapping(
		map[string]any{"count": 42},
		map[string]string{"count": "42"},
	)
	if matched {
		t.Fatal("expected mismatch for non-string claim value")
	}
	if failedClaim != "count" {
		t.Errorf("failedClaim = %q, want %q", failedClaim, "count")
	}
	if !strings.HasPrefix(got, "<type:") {
		t.Errorf("got = %q, expected <type:...> prefix", got)
	}
}

func TestEvalMapping_WildcardEmptyString(t *testing.T) {
	matched, failedClaim, want, got := evalMapping(
		map[string]any{"app_name": ""},
		map[string]string{"app_name": "*"},
	)
	if matched {
		t.Fatal("expected mismatch for empty wildcard value")
	}
	if failedClaim != "app_name" {
		t.Errorf("failedClaim = %q, want %q", failedClaim, "app_name")
	}
	if want != "*" {
		t.Errorf("want = %q, expected %q", want, "*")
	}
	if got != "<empty>" {
		t.Errorf("got = %q, want %q", got, "<empty>")
	}
}

func TestEvalMapping_WildcardNonEmptyMatches(t *testing.T) {
	matched, _, _, _ := evalMapping(
		map[string]any{"app_name": "my-app"},
		map[string]string{"app_name": "*"},
	)
	if !matched {
		t.Fatal("expected wildcard to match non-empty string")
	}
}

func TestEvalMapping_ValueMismatch(t *testing.T) {
	matched, failedClaim, want, got := evalMapping(
		map[string]any{"env": "staging"},
		map[string]string{"env": "prod"},
	)
	if matched {
		t.Fatal("expected mismatch for wrong claim value")
	}
	if failedClaim != "env" {
		t.Errorf("failedClaim = %q, want %q", failedClaim, "env")
	}
	if want != "prod" {
		t.Errorf("want = %q, expected %q", want, "prod")
	}
	if got != "staging" {
		t.Errorf("got = %q, expected %q", got, "staging")
	}
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
	if !matched {
		t.Fatal("expected array claim containing want to match")
	}
}

func TestEvalMapping_ArrayClaimNoMatchReportsElements(t *testing.T) {
	matched, failedClaim, want, got := evalMapping(
		map[string]any{"groups": []any{"plan:free"}},
		map[string]string{"groups": "plan:pro"},
	)
	if matched {
		t.Fatal("expected mismatch when array does not contain want")
	}
	if failedClaim != "groups" {
		t.Errorf("failedClaim = %q, want %q", failedClaim, "groups")
	}
	if want != "plan:pro" {
		t.Errorf("want = %q, expected %q", want, "plan:pro")
	}
	if got != "[plan:free]" {
		t.Errorf("got = %q, expected the array's contents", got)
	}
}

func TestEvalMapping_ArrayClaimWildcardMatchesNonEmpty(t *testing.T) {
	matched, _, _, _ := evalMapping(
		map[string]any{"groups": []any{"plan:free"}},
		map[string]string{"groups": "*"},
	)
	if !matched {
		t.Fatal("expected wildcard to match a non-empty array")
	}
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
	if len(roles) != 1 || roles[0] != "pro-tier" {
		t.Fatalf("expected [pro-tier], got %v", roles)
	}
}

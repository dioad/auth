package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntrospectionFromClaimsMap_DirectUnmarshalSucceeds(t *testing.T) {
	claims, err := introspectionFromClaimsMap(map[string]any{
		"aud": "single-audience",
		"sub": "test-user",
	})
	require.NoError(t, err)
	assert.Equal(t, "single-audience", claims.Audience)
	assert.Equal(t, "test-user", claims.Subject)
}

// TestIntrospectionFromClaimsMap_KeepsTheFirstAudienceWhenAudienceIsArray
// covers the documented compatibility case: some tokens emit "aud" as a
// JSON array, which IntrospectionResponse.Audience, a string field, holds as
// the first audience rather than surfacing the mismatch as an error.
func TestIntrospectionFromClaimsMap_KeepsTheFirstAudienceWhenAudienceIsArray(t *testing.T) {
	claims, err := introspectionFromClaimsMap(map[string]any{
		"aud": []string{"aud-1", "aud-2"},
		"sub": "test-user",
	})
	require.NoError(t, err)
	assert.Equal(t, "test-user", claims.Subject)
	assert.Equal(t, "aud-1", claims.Audience, "a list-typed aud decodes to its first audience")
}

// TestIntrospectionFromClaimsMap_ReturnsErrorWhenSanitizedStillFails covers
// the terminal error path: even after stripping "aud", a remaining
// type-incompatible field must surface as an error rather than a
// partially-populated zero-ish result.
func TestIntrospectionFromClaimsMap_ReturnsErrorWhenSanitizedStillFails(t *testing.T) {
	_, err := introspectionFromClaimsMap(map[string]any{
		"aud": []string{"aud-1", "aud-2"},
		"exp": "not-a-number",
	})
	assert.Error(t, err)
}

// TestIntrospectionFromClaimsMap_ReturnsErrorOnMarshalFailure covers the
// initial json.Marshal failure path. The unmarshalable value is placed on
// "aud" specifically: the sanitized retry deletes "aud" before its second
// marshal attempt, so if this function's early return on the first
// marshal error were ever skipped, the retry would silently succeed
// instead of surfacing the failure -- putting the bad value on any other
// key would let both attempts fail identically and hide that gap.
func TestIntrospectionFromClaimsMap_ReturnsErrorOnMarshalFailure(t *testing.T) {
	_, err := introspectionFromClaimsMap(map[string]any{
		"aud": make(chan int),
	})
	assert.Error(t, err)
}

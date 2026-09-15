package jwt

import (
	"testing"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/require"
)

func TestResolveSignatureAlgorithmsUsesDefaults(t *testing.T) {
	algorithms, err := ResolveSignatureAlgorithms("", nil, DefaultSignatureAlgorithms())
	require.NoError(t, err)
	require.Equal(t, []jwtvalidator.SignatureAlgorithm{jwtvalidator.RS256, jwtvalidator.ES384}, algorithms)
}

func TestResolveSignatureAlgorithmsUsesLegacySingleValue(t *testing.T) {
	algorithms, err := ResolveSignatureAlgorithms("es384", nil, DefaultSignatureAlgorithms())
	require.NoError(t, err)
	require.Equal(t, []jwtvalidator.SignatureAlgorithm{jwtvalidator.ES384}, algorithms)
}

func TestResolveSignatureAlgorithmsUsesMultiValue(t *testing.T) {
	algorithms, err := ResolveSignatureAlgorithms(
		"RS256",
		[]string{"RS256", "ES384", "RS256"},
		DefaultSignatureAlgorithms(),
	)
	require.NoError(t, err)
	require.Equal(t, []jwtvalidator.SignatureAlgorithm{jwtvalidator.RS256, jwtvalidator.ES384}, algorithms)
}

func TestResolveSignatureAlgorithmsRejectsInvalidEntries(t *testing.T) {
	_, err := ResolveSignatureAlgorithms("", []string{"RS256", "INVALID"}, DefaultSignatureAlgorithms())
	require.Error(t, err)

	_, err = ResolveSignatureAlgorithms("", []string{""}, DefaultSignatureAlgorithms())
	require.Error(t, err)
}

// TestResolveSignatureAlgorithmsSkipsOnlyDuplicateNotRemainingEntries covers
// the dedup loop's continue: the existing multi-value test places its
// duplicate last in the list, where continue and an accidental break behave
// identically (nothing remains to process either way). Placing the
// duplicate before a distinct entry proves the loop actually continues
// rather than aborting early and silently dropping the rest of the
// configured algorithms.
func TestResolveSignatureAlgorithmsSkipsOnlyDuplicateNotRemainingEntries(t *testing.T) {
	algorithms, err := ResolveSignatureAlgorithms(
		"",
		[]string{"RS256", "RS256", "ES384"},
		DefaultSignatureAlgorithms(),
	)
	require.NoError(t, err)
	require.Equal(t, []jwtvalidator.SignatureAlgorithm{jwtvalidator.RS256, jwtvalidator.ES384}, algorithms)
}

func TestResolveSignatureAlgorithmsRejectsInvalidSingleValue(t *testing.T) {
	_, err := ResolveSignatureAlgorithms("BOGUS", nil, DefaultSignatureAlgorithms())
	require.Error(t, err)
}

func TestResolveSignatureAlgorithmsRejectsEmptyConfiguration(t *testing.T) {
	_, err := ResolveSignatureAlgorithms("", nil, nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "no signature algorithms configured")
}

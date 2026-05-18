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

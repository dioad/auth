package jwt_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/jwt"
	"github.com/dioad/config/configcheck"
)

func TestValidatorConfig_ReadsKebabCaseKeys(t *testing.T) {
	t.Parallel()

	var cfg jwt.ValidatorConfig
	require.NoError(t, configcheck.Decode(map[string]any{
		"issuer":                     "https://issuer.example",
		"signature-algorithm":        "RS256",
		"signature-algorithms":       []any{"RS256", "ES256"},
		"cache-ttl-seconds":          120,
		"allowed-clock-skew-seconds": 30,
		"claim-predicates":           map[string]any{"role": "admin"},
	}, &cfg))

	assert.Equal(t, "RS256", cfg.SignatureAlgorithm)
	assert.Equal(t, []string{"RS256", "ES256"}, cfg.SignatureAlgorithms)
	assert.Equal(t, 120, cfg.CacheTTL)
	assert.Equal(t, 30, cfg.AllowedClockSkew)
	assert.Equal(t, map[string]any{"role": "admin"}, cfg.ClaimPredicate)
	assert.Empty(t, cfg.DeprecatedKeys())
}

func TestValidatorConfig_DeprecatedKeysReportsSnakeCaseKeys(t *testing.T) {
	t.Parallel()

	var cfg jwt.ValidatorConfig
	require.NoError(t, configcheck.Decode(map[string]any{
		"issuer":                     "https://issuer.example",
		"signature_algorithm":        "RS256",
		"signature_algorithms":       []any{"RS256", "ES256"},
		"cache_ttl_seconds":          120,
		"allowed_clock_skew_seconds": 30,
		"claim_predicates":           map[string]any{"role": "admin"},
	}, &cfg), "a strict decode still accepts the deprecated keys")

	assert.Equal(t, []string{
		"signature_algorithm",
		"signature_algorithms",
		"cache_ttl_seconds",
		"allowed_clock_skew_seconds",
		"claim_predicates",
	}, cfg.DeprecatedKeys())
}

// TestNewValidatorFromConfig_DeprecatedKeysStillTakeEffect pins that a
// deprecated key configures the validator, not merely that it decodes: an
// unsupported algorithm is only refused if the key was read.
func TestNewValidatorFromConfig_DeprecatedKeysStillTakeEffect(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"signature_algorithms", "signature-algorithms"} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()

			cfg := jwt.FromMap(map[string]any{
				"issuer": "https://issuer.example",
				key:      []any{"not-an-algorithm"},
			})

			_, err := jwt.NewValidatorFromConfig(&cfg)

			assert.ErrorContains(t, err, "resolving signature algorithms")
		})
	}
}

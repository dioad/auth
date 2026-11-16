package oidc_test

import (
	"maps"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/oidc"
	"github.com/dioad/config/configcheck"
	"github.com/dioad/config/configwalk"
)

// kebabCaseSettings sets every renamed key of a validator by its current name.
func kebabCaseSettings() map[string]any {
	return map[string]any{
		"issuer":                     "https://issuer.example",
		"cache-ttl-seconds":          120,
		"signature-algorithm":        "HS256",
		"signature-algorithms":       []any{"HS256", "HS384"},
		"allowed-clock-skew-seconds": 30,
		"claim-predicates":           map[string]any{"role": "admin"},
		"hmac-secret":                "0123456789abcdef0123456789abcdef",
		"allow-insecure-hmac":        true,
	}
}

// snakeCaseSettings is kebabCaseSettings as a config written for an earlier
// release names the keys.
func snakeCaseSettings() map[string]any {
	return map[string]any{
		"issuer":                     "https://issuer.example",
		"cache_ttl_seconds":          120,
		"signature_algorithm":        "HS256",
		"signature_algorithms":       []any{"HS256", "HS384"},
		"allowed_clock_skew_seconds": 30,
		"claim_predicates":           map[string]any{"role": "admin"},
		"hmac_secret":                "0123456789abcdef0123456789abcdef",
		"allow_insecure_hmac":        true,
	}
}

func TestValidatorConfig_ReadsKebabCaseKeys(t *testing.T) {
	t.Parallel()

	var cfg oidc.ValidatorConfig
	require.NoError(t, configcheck.Decode(kebabCaseSettings(), &cfg))

	assert.Equal(t, 120, cfg.CacheTTL)
	assert.Equal(t, "HS256", cfg.SignatureAlgorithm)
	assert.Equal(t, []string{"HS256", "HS384"}, cfg.SignatureAlgorithms)
	assert.Equal(t, 30, cfg.AllowedClockSkew)
	assert.Equal(t, map[string]any{"role": "admin"}, cfg.ClaimPredicate)
	assert.Equal(t, "0123456789abcdef0123456789abcdef", cfg.HMACSecret)
	assert.True(t, cfg.AllowInsecureHMAC)
	assert.Empty(t, cfg.DeprecatedKeys())
}

func TestValidatorConfig_DeprecatedKeysReportsSnakeCaseKeys(t *testing.T) {
	t.Parallel()

	var cfg oidc.ValidatorConfig
	require.NoError(t, configcheck.Decode(snakeCaseSettings(), &cfg), "a strict decode still accepts the deprecated keys")

	assert.Equal(t, []string{
		"cache_ttl_seconds",
		"signature_algorithm",
		"signature_algorithms",
		"allowed_clock_skew_seconds",
		"claim_predicates",
		"hmac_secret",
		"allow_insecure_hmac",
	}, cfg.DeprecatedKeys())
}

func TestValidatorConfig_StrictDecodeStillRejectsAnUnknownKey(t *testing.T) {
	t.Parallel()

	settings := kebabCaseSettings()
	settings["cache-ttl"] = 120

	err := configcheck.Decode(settings, new(oidc.ValidatorConfig))

	var findings *configcheck.Error
	require.ErrorAs(t, err, &findings)
	assert.Equal(t, []configcheck.Finding{{Path: "cache-ttl", Message: configcheck.UnknownKeyMessage}}, findings.Findings)
}

// TestNewValidatorFromConfig_DeprecatedKeysStillTakeEffect pins that a
// deprecated key configures the validator, not merely that it decodes: a
// restriction that silently stopped applying would admit more tokens.
func TestNewValidatorFromConfig_DeprecatedKeysStillTakeEffect(t *testing.T) {
	t.Parallel()

	const secret = "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name     string
		settings map[string]any
	}{
		{
			name: "snake_case keys",
			settings: map[string]any{
				"hmac_secret":         secret,
				"allow_insecure_hmac": true,
				"audiences":           []any{"my-api"},
				"claim_predicates":    map[string]any{"role": "admin"},
			},
		},
		{
			name: "kebab-case keys",
			settings: map[string]any{
				"hmac-secret":         secret,
				"allow-insecure-hmac": true,
				"audiences":           []any{"my-api"},
				"claim-predicates":    map[string]any{"role": "admin"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var cfg oidc.ValidatorConfig
			require.NoError(t, configcheck.Decode(tt.settings, &cfg))
			validator, err := oidc.NewValidatorFromConfig(&cfg)
			require.NoError(t, err)

			_, err = validator.ValidateToken(t.Context(), signHS256(t, secret, map[string]any{"role": "admin"}))
			require.NoError(t, err, "a token that satisfies the claim predicate is accepted")

			_, err = validator.ValidateToken(t.Context(), signHS256(t, secret, map[string]any{"role": "guest"}))
			assert.Error(t, err, "the claim predicate is enforced")
		})
	}
}

func TestNewValidatorFromConfig_KebabCaseKeyWinsOverItsDeprecatedKey(t *testing.T) {
	t.Parallel()

	const secret = "0123456789abcdef0123456789abcdef"
	var cfg oidc.ValidatorConfig
	require.NoError(t, configcheck.Decode(map[string]any{
		"hmac-secret":         secret,
		"hmac_secret":         "ffffffffffffffffffffffffffffffff",
		"allow-insecure-hmac": true,
		"audiences":           []any{"my-api"},
	}, &cfg))
	validator, err := oidc.NewValidatorFromConfig(&cfg)
	require.NoError(t, err)

	_, err = validator.ValidateToken(t.Context(), signHS256(t, secret, nil))

	assert.NoError(t, err)
}

func TestKeyFetchingIssuers_SkipsAValidatorWithADeprecatedHMACSecret(t *testing.T) {
	t.Parallel()

	var cfg oidc.ValidatorConfig
	require.NoError(t, configcheck.Decode(map[string]any{
		"issuer":      "https://issuer.example",
		"hmac_secret": "0123456789abcdef0123456789abcdef",
	}, &cfg))

	assert.Empty(t, oidc.KeyFetchingIssuers([]oidc.ValidatorConfig{cfg}))
}

// TestValidatorConfig_OnlyDeprecatedKeysBreakTheNamingRules pins that every
// key a new config should use is kebab-case, and that the snake_case keys left
// are exactly the deprecated ones.
func TestValidatorConfig_OnlyDeprecatedKeysBreakTheNamingRules(t *testing.T) {
	t.Parallel()

	problems := configwalk.KeyNamingProblems(reflect.TypeFor[oidc.ValidatorConfig]())
	fields := make([]string, len(problems))
	for i, problem := range problems {
		fields[i] = problem.Field + ": " + problem.Key
	}

	assert.ElementsMatch(t, []string{
		"oidc.deprecatedValidatorKeys.DeprecatedCacheTTL: cache_ttl_seconds",
		"oidc.deprecatedValidatorKeys.DeprecatedSignatureAlgorithm: signature_algorithm",
		"oidc.deprecatedValidatorKeys.DeprecatedSignatureAlgorithms: signature_algorithms",
		"oidc.deprecatedValidatorKeys.DeprecatedAllowedClockSkew: allowed_clock_skew_seconds",
		"oidc.deprecatedValidatorKeys.DeprecatedClaimPredicate: claim_predicates",
		"oidc.deprecatedValidatorKeys.DeprecatedHMACSecret: hmac_secret",
		"oidc.deprecatedValidatorKeys.DeprecatedAllowInsecureHMAC: allow_insecure_hmac",
	}, fields)
}

// signHS256 signs a token for audience "my-api" carrying extra claims.
func signHS256(t *testing.T, secret string, extra map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "alice",
		"iss": "https://idp.example",
		"aud": "my-api",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	maps.Copy(claims, extra)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	require.NoError(t, err)
	return token
}

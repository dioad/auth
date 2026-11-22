package jwt

import (
	"cmp"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/rs/zerolog/log"
)

// ValidatorConfig contains configuration for a JWT token validator.
//
// Its keys are kebab-case. The snake_case keys of earlier releases, such as
// cache_ttl_seconds, are still read but deprecated: see DeprecatedKeys.
type ValidatorConfig struct {
	deprecatedValidatorKeys `mapstructure:",squash"`

	// Issuer is the expected token "iss" claim. Signing keys are discovered
	// from its JWKS endpoint. Required.
	Issuer string `json:"issuer" mapstructure:"issuer" desc:"expected token iss claim; signing keys are discovered from its JWKS endpoint"`
	// Audiences lists the accepted values of the token "aud" claim. A token is
	// accepted if it carries at least one of them.
	Audiences []string `json:"audiences" mapstructure:"audiences" desc:"accepted values of the token aud claim; a token is accepted if it carries at least one"`
	// SignatureAlgorithm is a single accepted signing algorithm, for example
	// "RS256". Ignored when SignatureAlgorithms is set.
	SignatureAlgorithm string `json:"signature_algorithm" mapstructure:"signature-algorithm" desc:"single accepted signing algorithm, for example RS256; ignored when signature algorithms is set"`
	// SignatureAlgorithms lists the accepted signing algorithms, for example
	// ["RS256", "ES256"]. Takes precedence over SignatureAlgorithm.
	SignatureAlgorithms []string `json:"signature_algorithms" mapstructure:"signature-algorithms" desc:"accepted signing algorithms, for example RS256 and ES256; takes precedence over the single signature algorithm"`
	// CacheTTL is how long, in seconds, discovered signing keys are cached.
	// Defaults to 300 when unset or not positive.
	CacheTTL int `json:"cache_ttl_seconds" mapstructure:"cache-ttl-seconds" desc:"how long, in seconds, discovered signing keys are cached"`
	// AllowedClockSkew is the tolerance, in seconds, applied to the token
	// "exp", "nbf" and "iat" claims. Defaults to 60 when unset or not positive.
	AllowedClockSkew int `json:"allowed_clock_skew_seconds" mapstructure:"allowed-clock-skew-seconds" desc:"tolerance, in seconds, applied to the token exp, nbf and iat claims"`
	// Debug enables debug logging of each token validation attempt and its
	// outcome. Intended for troubleshooting.
	Debug bool `json:"debug" mapstructure:"debug" desc:"log each token validation attempt and its outcome, for troubleshooting"`
	// ClaimPredicate restricts which tokens are accepted by their claims. Each
	// key is a claim name and its value is the required claim value; an array
	// claim matches when it contains the value. All entries must match. Use
	// the reserved keys "and" and "or", each holding a list of such maps, for
	// nested combinations.
	ClaimPredicate map[string]any `json:"claim_predicates" mapstructure:"claim-predicates" desc:"required claim values keyed by claim name; an array claim matches when it contains the value and all entries must match"`
}

// deprecatedValidatorKeys reads the snake_case keys ValidatorConfig used
// before its keys became kebab-case, so that a config written for an earlier
// release still loads. Each field stands in for the ValidatorConfig field of
// the same name when that one is unset; see ValidatorConfig.DeprecatedKeys.
// The keys will be removed in a later release.
type deprecatedValidatorKeys struct {
	// Deprecated: set SignatureAlgorithm, read from signature-algorithm.
	DeprecatedSignatureAlgorithm string `json:"-" mapstructure:"signature_algorithm" flag:",hidden"`
	// Deprecated: set SignatureAlgorithms, read from signature-algorithms.
	DeprecatedSignatureAlgorithms []string `json:"-" mapstructure:"signature_algorithms" flag:",hidden"`
	// Deprecated: set CacheTTL, read from cache-ttl-seconds.
	DeprecatedCacheTTL int `json:"-" mapstructure:"cache_ttl_seconds" flag:",hidden"`
	// Deprecated: set AllowedClockSkew, read from allowed-clock-skew-seconds.
	DeprecatedAllowedClockSkew int `json:"-" mapstructure:"allowed_clock_skew_seconds" flag:",hidden"`
	// Deprecated: set ClaimPredicate, read from claim-predicates.
	DeprecatedClaimPredicate map[string]any `json:"-" mapstructure:"claim_predicates" flag:",hidden"`
}

// DeprecatedKeys returns the deprecated snake_case keys c was loaded with,
// such as "cache_ttl_seconds", so a service can tell its operator to rename
// them. The replacement of each is the same name in kebab-case. Building a
// validator from c logs a warning for each.
func (c ValidatorConfig) DeprecatedKeys() []string {
	d := c.deprecatedValidatorKeys
	var keys []string
	add := func(set bool, key string) {
		if set {
			keys = append(keys, key)
		}
	}
	add(d.DeprecatedSignatureAlgorithm != "", "signature_algorithm")
	add(len(d.DeprecatedSignatureAlgorithms) > 0, "signature_algorithms")
	add(d.DeprecatedCacheTTL != 0, "cache_ttl_seconds")
	add(d.DeprecatedAllowedClockSkew != 0, "allowed_clock_skew_seconds")
	add(len(d.DeprecatedClaimPredicate) > 0, "claim_predicates")
	return keys
}

// withDeprecatedKeys returns c with each field that is unset taking the value
// of its deprecated key. A field set by its kebab-case key keeps that value.
// Everything that reads the renamed fields must read them from the result.
func (c ValidatorConfig) withDeprecatedKeys() ValidatorConfig {
	d := c.deprecatedValidatorKeys
	c.SignatureAlgorithm = cmp.Or(c.SignatureAlgorithm, d.DeprecatedSignatureAlgorithm)
	if len(c.SignatureAlgorithms) == 0 {
		c.SignatureAlgorithms = d.DeprecatedSignatureAlgorithms
	}
	c.CacheTTL = cmp.Or(c.CacheTTL, d.DeprecatedCacheTTL)
	c.AllowedClockSkew = cmp.Or(c.AllowedClockSkew, d.DeprecatedAllowedClockSkew)
	if len(c.ClaimPredicate) == 0 {
		c.ClaimPredicate = d.DeprecatedClaimPredicate
	}
	return c
}

// WarnDeprecatedKeys logs a warning for each of keys, the deprecated
// snake_case keys a validator config for issuer was loaded with, naming the
// kebab-case key that replaces it. It logs to the global logger because
// validators are built at startup, before any request has a logger.
func WarnDeprecatedKeys(issuer string, keys []string) {
	for _, key := range keys {
		log.Warn().
			Str("issuer", issuer).
			Str("config_key", key).
			Str("replacement", strings.ReplaceAll(key, "_", "-")).
			Msg("validator config key is deprecated and will stop being read in a later release")
	}
}

// FromMap creates a ValidatorConfig from a map.
func FromMap(m map[string]any) ValidatorConfig {
	var c ValidatorConfig
	_ = mapstructure.Decode(m, &c)
	return c
}

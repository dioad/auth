package jwt

import "github.com/go-viper/mapstructure/v2"

// ValidatorConfig contains configuration for a JWT token validator.
type ValidatorConfig struct {
	// Issuer is the expected token "iss" claim. Signing keys are discovered
	// from its JWKS endpoint. Required.
	Issuer string `json:"issuer" mapstructure:"issuer"`
	// Audiences lists the accepted values of the token "aud" claim. A token is
	// accepted if it carries at least one of them.
	Audiences []string `json:"audiences" mapstructure:"audiences"`
	// SignatureAlgorithm is a single accepted signing algorithm, for example
	// "RS256". Ignored when SignatureAlgorithms is set.
	SignatureAlgorithm string `json:"signature_algorithm" mapstructure:"signature_algorithm"`
	// SignatureAlgorithms lists the accepted signing algorithms, for example
	// ["RS256", "ES256"]. Takes precedence over SignatureAlgorithm.
	SignatureAlgorithms []string `json:"signature_algorithms" mapstructure:"signature_algorithms"`
	// CacheTTL is how long, in seconds, discovered signing keys are cached.
	// Defaults to 300 when unset or not positive.
	CacheTTL int `json:"cache_ttl_seconds" mapstructure:"cache_ttl_seconds"`
	// AllowedClockSkew is the tolerance, in seconds, applied to the token
	// "exp", "nbf" and "iat" claims. Defaults to 60 when unset or not positive.
	AllowedClockSkew int `json:"allowed_clock_skew_seconds" mapstructure:"allowed_clock_skew_seconds"`
	// Debug enables debug logging of each token validation attempt and its
	// outcome. Intended for troubleshooting.
	Debug bool `json:"debug" mapstructure:"debug"`
	// ClaimPredicate restricts which tokens are accepted by their claims. Each
	// key is a claim name and its value is the required claim value; an array
	// claim matches when it contains the value. All entries must match. Use
	// the reserved keys "and" and "or", each holding a list of such maps, for
	// nested combinations.
	ClaimPredicate map[string]any `json:"claim_predicates" mapstructure:"claim_predicates"`
}

// FromMap creates a ValidatorConfig from a map.
func FromMap(m map[string]any) ValidatorConfig {
	var c ValidatorConfig
	_ = mapstructure.Decode(m, &c)
	return c
}

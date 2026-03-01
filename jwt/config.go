package jwt

import "github.com/go-viper/mapstructure/v2"

// ValidatorConfig contains configuration for a JWT token validator.
type ValidatorConfig struct {
	Issuer             string         `json:"issuer" mapstructure:"issuer"`
	Audiences          []string       `json:"audiences" mapstructure:"audiences"`
	SignatureAlgorithm string         `json:"signature_algorithm" mapstructure:"signature_algorithm"`
	CacheTTL           int            `json:"cache_ttl_seconds" mapstructure:"cache_ttl_seconds"`
	AllowedClockSkew   int            `json:"allowed_clock_skew_seconds" mapstructure:"allowed_clock_skew_seconds"`
	Debug              bool           `json:"debug" mapstructure:"debug"`
	ClaimPredicate     map[string]any `json:"claim_predicates" mapstructure:"claim_predicates"`
}

// FromMap creates a ValidatorConfig from a map.
func FromMap(m map[string]any) ValidatorConfig {
	var c ValidatorConfig
	_ = mapstructure.Decode(m, &c)
	return c
}

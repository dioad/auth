package oidc

import (
	"github.com/dioad/util"

	"github.com/dioad/net/tls"
)

// EndpointConfig describes the issuer endpoint and any provider-specific options.
type EndpointConfig struct {
	Type          string `json:"type,omitempty" mapstructure:"type,omitempty"`
	URL           string `json:"url" mapstructure:"url"`
	KeycloakRealm string `json:"keycloak_realm,omitempty" mapstructure:"keycloak-realm,omitempty"`
}

// ClientConfig captures client credentials and token acquisition options for an OIDC provider.
type ClientConfig struct {
	// Provider     EndpointConfig    `json:"provider"` // e.g. "github", "keycloak"
	EndpointConfig `mapstructure:",squash"`
	ClientID       string            `json:"client_id" mapstructure:"client-id"`
	ClientSecret   util.MaskedString `json:"client_secret" mapstructure:"client-secret,omitempty"`

	Audience string `json:"audience,omitempty" mapstructure:"audience,omitempty"`

	// do these belong somewhere else?
	TokenFile string `json:"token_file,omitempty" mapstructure:"token-file,omitempty"`

	TLSClient tls.ClientConfig `json:"tls_client" mapstructure:"tls-client,omitempty"`
}

// ValidatorConfig controls validation behavior for issued tokens.
type ValidatorConfig struct {
	EndpointConfig     `mapstructure:",squash"`
	Audiences          []string       `json:"audiences" mapstructure:"audiences"`
	Issuer             string         `json:"issuer" mapstructure:"issuer"`
	CacheTTL           int            `json:"cache_ttl_seconds" mapsstructure:"cache_ttl_seconds"`
	SignatureAlgorithm string         `json:"signature_algorithm" mapstructure:"signature_algorithm"`
	AllowedClockSkew   int            `json:"allowed_clock_skew_seconds" mapstructure:"allowed_clock_skew_seconds"`
	Debug              bool           `json:"debug" mapstructure:"debug"`
	ClaimPredicate     map[string]any `json:"claim_predicates" mapstructure:"claim_predicates"`
	// HMACSecret is an optional shared secret for HS256/HS384/HS512 token
	// validation. When non-empty, JWKS discovery is skipped and the secret is
	// used directly as the signing key. Intended for local development and
	// smoke testing only; never use a static shared secret in production.
	HMACSecret string `json:"hmac_secret,omitempty" mapstructure:"hmac_secret"`
}

// TrustConfig describes a set of validators that must all succeed.
type TrustConfig struct {
	Verifiers []ValidatorConfig `json:"validators" mapstructure:"validators"`
}

// ProviderConfig represents a single web provider configuration for Goth callbacks.
type ProviderConfig struct {
	ClientID     string `json:"client_id" mapstructure:"client-id"`
	ClientSecret string `json:"client_secret" mapstructure:"client-secret"`
	Callback     string `json:"callback" mapstructure:"callback"`
}

// ProviderMap indexes provider configurations by name.
type ProviderMap map[string]ProviderConfig

// Config contains a collection of provider configurations.
type Config struct {
	ProviderMap ProviderMap `json:"providers" mapstructure:"providers"`
}

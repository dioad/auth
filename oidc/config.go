package oidc

import (
	"github.com/dioad/util"

	"github.com/dioad/net/tls"
)

// EndpointConfig describes the issuer endpoint and any provider-specific options.
type EndpointConfig struct {
	// Type selects a provider-specific behaviour. Accepted values are "github",
	// "githubactions", "keycloak", "flyio" and "aws". Leave empty for a
	// generic OIDC provider discovered from URL.
	Type string `json:"type,omitempty" mapstructure:"type,omitempty"`
	// URL is the OIDC issuer URL, for example "https://accounts.example.com".
	// Provider metadata and signing keys are discovered from it.
	URL string `json:"url" mapstructure:"url"`
	// KeycloakRealm is the Keycloak realm name. It is only used when Type is
	// "keycloak".
	KeycloakRealm string `json:"keycloak_realm,omitempty" mapstructure:"keycloak-realm,omitempty"`
}

// Recognised EndpointConfig.Type values.
const (
	ProviderTypeGitHub        = "github"
	ProviderTypeGitHubActions = "githubactions"
	ProviderTypeKeycloak      = "keycloak"
	ProviderTypeFlyIO         = "flyio"
	ProviderTypeAWS           = "aws"
)

// ClientConfig captures client credentials and token acquisition options for an OIDC provider.
type ClientConfig struct {
	// Provider     EndpointConfig    `json:"provider"` // e.g. "github", "keycloak"
	EndpointConfig `mapstructure:",squash"`

	// ClientID is the OAuth 2.0 client identifier registered with the provider.
	ClientID string `json:"client_id" mapstructure:"client-id"`
	// ClientSecret is the OAuth 2.0 client secret, used for the client
	// credentials flow.
	ClientSecret util.MaskedString `json:"client_secret" mapstructure:"client-secret,omitempty"`

	// Audience is the audience requested for issued tokens. It is required by
	// platform identity providers such as "githubactions", "flyio" and "aws"
	// and ignored by providers that do not support it.
	Audience string `json:"audience,omitempty" mapstructure:"audience,omitempty"`

	// TokenFile is the path to a file used to persist the interactive login
	// token between runs. When set, the token is loaded from the file and
	// refreshed with its refresh token once it expires.
	TokenFile string `json:"token_file,omitempty" mapstructure:"token-file,omitempty"`

	// TLSClient configures TLS for connections to the provider, such as a
	// custom CA bundle.
	TLSClient tls.ClientConfig `json:"tls_client" mapstructure:"tls-client,omitempty"`
}

// ValidatorConfig controls validation behavior for issued tokens.
type ValidatorConfig struct {
	EndpointConfig `mapstructure:",squash"`

	// Audiences lists the accepted values of the token "aud" claim. A token is
	// accepted if it carries at least one of them.
	Audiences []string `json:"audiences" mapstructure:"audiences"`
	// Issuer is the expected token "iss" claim. Signing keys are discovered
	// from its JWKS endpoint.
	Issuer string `json:"issuer" mapstructure:"issuer"`
	// CacheTTL is how long, in seconds, discovered signing keys are cached.
	// Defaults to 300 when unset or not positive.
	CacheTTL int `json:"cache_ttl_seconds" mapstructure:"cache_ttl_seconds"`
	// SignatureAlgorithm is a single accepted signing algorithm, for example
	// "RS256". Ignored when SignatureAlgorithms is set.
	SignatureAlgorithm string `json:"signature_algorithm" mapstructure:"signature_algorithm"`
	// SignatureAlgorithms lists the accepted signing algorithms, for example
	// ["RS256", "ES256"]. Takes precedence over SignatureAlgorithm.
	SignatureAlgorithms []string `json:"signature_algorithms" mapstructure:"signature_algorithms"`
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
	// HMACSecret is an optional shared secret for HS256/HS384/HS512 token
	// validation. When non-empty, JWKS discovery is skipped and the secret is
	// used directly as the signing key. Intended for local development and
	// smoke testing only; never use a static shared secret in production.
	// Requires AllowInsecureHMAC: true to prevent accidental production use.
	HMACSecret string `json:"hmac_secret,omitempty" mapstructure:"hmac_secret"`

	// AllowInsecureHMAC must be set to true when HMACSecret is used. This
	// explicit opt-in acknowledges that HMAC shared secrets are not suitable
	// for production deployments. Never set this to true in production config.
	AllowInsecureHMAC bool `json:"allow_insecure_hmac,omitempty" mapstructure:"allow_insecure_hmac"`
}

// TrustConfig describes a set of validators that must all succeed.
type TrustConfig struct {
	Verifiers []ValidatorConfig `json:"validators" mapstructure:"validators"`
}

// ProviderConfig represents a single web provider configuration for Goth callbacks.
type ProviderConfig struct {
	ClientID     string `json:"client_id"     mapstructure:"client-id"`
	ClientSecret string `json:"client_secret" mapstructure:"client-secret"`
	Callback     string `json:"callback"      mapstructure:"callback"`
	// Scopes is optional and only used by browser/login-oriented integrations.
	Scopes []string `json:"scopes,omitzero" mapstructure:"scopes,omitzero"`
	// DiscoveryURL is optional and allows overriding provider discovery behavior
	// in integrations that support explicit discovery endpoints.
	DiscoveryURL string `json:"discovery_url,omitzero" mapstructure:"discovery-url,omitzero"`
}

// ProviderMap indexes provider configurations by name.
type ProviderMap map[string]ProviderConfig

// Config contains a collection of provider configurations.
type Config struct {
	ProviderMap ProviderMap `json:"providers" mapstructure:"providers"`
}

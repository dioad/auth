package oidc

import (
	"cmp"

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
	// credentials flow. Set at most one of ClientSecret and ClientSecretFile.
	ClientSecret util.MaskedString `json:"client_secret" mapstructure:"client-secret,omitempty"`
	// ClientSecretFile is the path to a file containing the client secret, for
	// example a mounted container secret. Surrounding whitespace is trimmed.
	// The file is read when the token source is built, not when the config is
	// validated; an unreadable or empty file is an error. Set at most one of
	// ClientSecret and ClientSecretFile.
	ClientSecretFile string `json:"client_secret_file,omitempty" mapstructure:"client-secret-file,omitempty"`

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
//
// Its keys are kebab-case. The snake_case keys of earlier releases, such as
// cache_ttl_seconds, are still read but deprecated: see DeprecatedKeys.
type ValidatorConfig struct {
	EndpointConfig          `mapstructure:",squash"`
	deprecatedValidatorKeys `mapstructure:",squash"`

	// Audiences lists the accepted values of the token "aud" claim. A token is
	// accepted if it carries at least one of them.
	Audiences []string `json:"audiences" mapstructure:"audiences"`
	// Issuer is the expected token "iss" claim. Signing keys are discovered
	// from its JWKS endpoint.
	Issuer string `json:"issuer" mapstructure:"issuer"`
	// CacheTTL is how long, in seconds, discovered signing keys are cached.
	// Defaults to 300 when unset or not positive.
	CacheTTL int `json:"cache_ttl_seconds" mapstructure:"cache-ttl-seconds"`
	// SignatureAlgorithm is a single accepted signing algorithm, for example
	// "RS256". Ignored when SignatureAlgorithms is set.
	SignatureAlgorithm string `json:"signature_algorithm" mapstructure:"signature-algorithm"`
	// SignatureAlgorithms lists the accepted signing algorithms, for example
	// ["RS256", "ES256"]. Takes precedence over SignatureAlgorithm.
	SignatureAlgorithms []string `json:"signature_algorithms" mapstructure:"signature-algorithms"`
	// AllowedClockSkew is the tolerance, in seconds, applied to the token
	// "exp", "nbf" and "iat" claims. Defaults to 60 when unset or not positive.
	AllowedClockSkew int `json:"allowed_clock_skew_seconds" mapstructure:"allowed-clock-skew-seconds"`
	// Debug enables debug logging of each token validation attempt and its
	// outcome. Intended for troubleshooting.
	Debug bool `json:"debug" mapstructure:"debug"`
	// ClaimPredicate restricts which tokens are accepted by their claims. Each
	// key is a claim name and its value is the required claim value; an array
	// claim matches when it contains the value. All entries must match. Use
	// the reserved keys "and" and "or", each holding a list of such maps, for
	// nested combinations.
	ClaimPredicate map[string]any `json:"claim_predicates" mapstructure:"claim-predicates"`
	// HMACSecret is an optional shared secret for HS256/HS384/HS512 token
	// validation. When non-empty, JWKS discovery is skipped and the secret is
	// used directly as the signing key. Intended for local development and
	// smoke testing only; never use a static shared secret in production.
	// Requires AllowInsecureHMAC: true to prevent accidental production use.
	HMACSecret string `json:"hmac_secret,omitempty" mapstructure:"hmac-secret"`

	// AllowInsecureHMAC must be set to true when HMACSecret is used. This
	// explicit opt-in acknowledges that HMAC shared secrets are not suitable
	// for production deployments. Never set this to true in production config.
	AllowInsecureHMAC bool `json:"allow_insecure_hmac,omitempty" mapstructure:"allow-insecure-hmac"`
}

// deprecatedValidatorKeys reads the snake_case keys ValidatorConfig used
// before its keys became kebab-case, so that a config written for an earlier
// release still loads. Each field stands in for the ValidatorConfig field of
// the same name when that one is unset; see ValidatorConfig.DeprecatedKeys.
// The keys will be removed in a later release.
type deprecatedValidatorKeys struct {
	// Deprecated: set CacheTTL, read from cache-ttl-seconds.
	DeprecatedCacheTTL int `json:"-" mapstructure:"cache_ttl_seconds"`
	// Deprecated: set SignatureAlgorithm, read from signature-algorithm.
	DeprecatedSignatureAlgorithm string `json:"-" mapstructure:"signature_algorithm"`
	// Deprecated: set SignatureAlgorithms, read from signature-algorithms.
	DeprecatedSignatureAlgorithms []string `json:"-" mapstructure:"signature_algorithms"`
	// Deprecated: set AllowedClockSkew, read from allowed-clock-skew-seconds.
	DeprecatedAllowedClockSkew int `json:"-" mapstructure:"allowed_clock_skew_seconds"`
	// Deprecated: set ClaimPredicate, read from claim-predicates.
	DeprecatedClaimPredicate map[string]any `json:"-" mapstructure:"claim_predicates"`
	// Deprecated: set HMACSecret, read from hmac-secret.
	DeprecatedHMACSecret string `json:"-" mapstructure:"hmac_secret"`
	// Deprecated: set AllowInsecureHMAC, read from allow-insecure-hmac.
	DeprecatedAllowInsecureHMAC bool `json:"-" mapstructure:"allow_insecure_hmac"`
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
	add(d.DeprecatedCacheTTL != 0, "cache_ttl_seconds")
	add(d.DeprecatedSignatureAlgorithm != "", "signature_algorithm")
	add(len(d.DeprecatedSignatureAlgorithms) > 0, "signature_algorithms")
	add(d.DeprecatedAllowedClockSkew != 0, "allowed_clock_skew_seconds")
	add(len(d.DeprecatedClaimPredicate) > 0, "claim_predicates")
	add(d.DeprecatedHMACSecret != "", "hmac_secret")
	add(d.DeprecatedAllowInsecureHMAC, "allow_insecure_hmac")
	return keys
}

// withDeprecatedKeys returns c with each field that is unset taking the value
// of its deprecated key. A field set by its kebab-case key keeps that value.
// Everything that reads the renamed fields must read them from the result.
func (c ValidatorConfig) withDeprecatedKeys() ValidatorConfig {
	d := c.deprecatedValidatorKeys
	c.CacheTTL = cmp.Or(c.CacheTTL, d.DeprecatedCacheTTL)
	c.SignatureAlgorithm = cmp.Or(c.SignatureAlgorithm, d.DeprecatedSignatureAlgorithm)
	if len(c.SignatureAlgorithms) == 0 {
		c.SignatureAlgorithms = d.DeprecatedSignatureAlgorithms
	}
	c.AllowedClockSkew = cmp.Or(c.AllowedClockSkew, d.DeprecatedAllowedClockSkew)
	if len(c.ClaimPredicate) == 0 {
		c.ClaimPredicate = d.DeprecatedClaimPredicate
	}
	c.HMACSecret = cmp.Or(c.HMACSecret, d.DeprecatedHMACSecret)
	c.AllowInsecureHMAC = c.AllowInsecureHMAC || d.DeprecatedAllowInsecureHMAC
	return c
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

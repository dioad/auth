package oidc

const (
	// SessionCookieName is the name of the cookie used to store the OIDC session.
	SessionCookieName = "dioad_session"
	// PreAuthRefererCookieName is the name of the cookie used to store the referer URL before authentication.
	PreAuthRefererCookieName = "auth_referer"
)

// ProviderConfig contains configuration for an OIDC provider.
type ProviderConfig struct {
	ClientID     string   `mapstructure:"client-id"`
	ClientSecret string   `mapstructure:"client-secret"`
	Callback     string   `mapstructure:"callback"`
	Scopes       []string `mapstructure:"scopes"`        // OAuth2 Scopes - Optional
	DiscoveryURL string   `mapstructure:"discovery-url"` // OpenID Connect Discovery URL - Optional
}

// ProviderMap maps provider names to their configurations.
type ProviderMap map[string]ProviderConfig

// Config contains configuration for OIDC authentication.
type Config struct {
	ProviderMap ProviderMap `mapstructure:"providers"`
}

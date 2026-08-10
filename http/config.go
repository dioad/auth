package http

import (
	"github.com/dioad/auth/http/basic"
	"github.com/dioad/auth/http/github"
	"github.com/dioad/auth/http/hmac"
	oidcmw "github.com/dioad/auth/http/middleware/oidc"
	"github.com/dioad/auth/jwt"
	"github.com/dioad/auth/oidc"
)

// OIDCServerConfig combines OIDC provider credentials with the login/session
// middleware settings (redirect-uri, cookies, login/logout paths) needed to
// complete a login when "type: oidc" is used as a server's sole auth gate.
type OIDCServerConfig struct {
	oidc.ClientConfig `mapstructure:",squash"`
	oidcmw.OIDCConfig `mapstructure:",squash"`
}

// ClientConfig represents the authentication configuration for an HTTP client.
type ClientConfig struct {
	BasicAuthConfig  basic.ClientConfig  `mapstructure:"basic"`
	GitHubAuthConfig github.ClientConfig `mapstructure:"github"`
	HMACAuthConfig   hmac.ClientConfig   `mapstructure:"hmac"`
}

// GenericAuthConfig represents a generic authentication configuration.
type GenericAuthConfig struct {
	Name   string         `mapstructure:"name"`
	Config map[string]any `mapstructure:"config"`
}

// ServerConfig represents the authentication configuration for an HTTP server.
type ServerConfig struct {
	// Type selects the auth handler explicitly: "github", "basic", "hmac", "jwt", "oidc".
	// When set it takes precedence over zero-value detection. An unrecognised Type
	// returns an error from NewHandler.
	Type string `mapstructure:"type"`

	BasicAuthConfig  basic.ServerConfig  `mapstructure:"basic"`
	GitHubAuthConfig github.ServerConfig `mapstructure:"github"`
	HMACAuthConfig   hmac.ServerConfig   `mapstructure:"hmac"`
	JWTAuthConfig    jwt.ValidatorConfig `mapstructure:"jwt"`
	OIDCAuthConfig   OIDCServerConfig    `mapstructure:"oidc"`

	Providers []string `mapstructure:"providers"`
}

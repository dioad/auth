package http

import (
	"github.com/dioad/auth/http/basic"
	"github.com/dioad/auth/http/github"
	"github.com/dioad/auth/http/hmac"
	"github.com/dioad/auth/jwt"
	"github.com/dioad/auth/oidc"
)

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
	BasicAuthConfig  basic.ServerConfig  `mapstructure:"basic"`
	GitHubAuthConfig github.ServerConfig `mapstructure:"github"`
	HMACAuthConfig   hmac.ServerConfig   `mapstructure:"hmac"`
	JWTAuthConfig    jwt.ValidatorConfig `mapstructure:"jwt"`
	OIDCAuthConfig   oidc.ClientConfig   `mapstructure:"oidc"`

	Providers []string `mapstructure:"providers"`
}

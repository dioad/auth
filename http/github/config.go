package github

import (
	"github.com/go-viper/mapstructure/v2"

	"github.com/dioad/net/authz"
)

// CommonConfig contains shared configuration for GitHub authentication.
type CommonConfig struct {
	AllowInsecureHTTP bool   `mapstructure:"allow-insecure-http" desc:"allow GitHub authentication over plain HTTP, for local development only"`
	ClientID          string `mapstructure:"client-id" desc:"GitHub OAuth application client identifier"`
	ClientSecret      string `mapstructure:"client-secret" desc:"GitHub OAuth application client secret"`

	// ConfigFile containing ClientID and ClientSecret
	ConfigFile string `mapstructure:"config-file" desc:"file containing the client id and client secret"`
}

// ClientConfig contains configuration for a GitHub authentication client.
type ClientConfig struct {
	CommonConfig `mapstructure:",squash"`

	AccessToken                      string `mapstructure:"access-token" desc:"GitHub access token"`
	AccessTokenFile                  string `mapstructure:"access-token-file" desc:"file containing a GitHub access token"`
	EnableAccessTokenFromEnvironment bool   `mapstructure:"enable-access-token-from-environment" desc:"read the access token from an environment variable"`
	EnvironmentVariableName          string `mapstructure:"environment-variable-name" desc:"name of the environment variable holding the access token"`
}

// ServerConfig contains configuration for a GitHub authentication server.
type ServerConfig struct {
	CommonConfig `mapstructure:",squash"`

	PrincipalACLConfig authz.PrincipalACLConfig `mapstructure:"principals"`
}

// FromMap creates a ServerConfig from a map.
func FromMap(m map[string]any) ServerConfig {
	var c ServerConfig
	_ = mapstructure.Decode(m, &c)
	return c
}

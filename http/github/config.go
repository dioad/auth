package github

import (
	"github.com/go-viper/mapstructure/v2"

	"github.com/dioad/net/authz"
)

// CommonConfig contains shared configuration for GitHub authentication.
type CommonConfig struct {
	AllowInsecureHTTP bool   `mapstructure:"allow-insecure-http"`
	ClientID          string `mapstructure:"client-id"`
	ClientSecret      string `mapstructure:"client-secret"`

	// ConfigFile containing ClientID and ClientSecret
	ConfigFile string `mapstructure:"config-file"`
}

// ClientConfig contains configuration for a GitHub authentication client.
type ClientConfig struct {
	CommonConfig                     `mapstructure:",squash"`
	AccessToken                      string `mapstructure:"access-token"`
	AccessTokenFile                  string `mapstructure:"access-token-file"`
	EnableAccessTokenFromEnvironment bool   `mapstructure:"enable-access-token-from-environment"`
	EnvironmentVariableName          string `mapstructure:"environment-variable-name"`
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

package oidc

import (
	"testing"

	"github.com/stretchr/testify/require"

	authoidc "github.com/dioad/auth/oidc"
)

func TestConfigAliases_CompatibleWithCanonicalOIDCConfig(t *testing.T) {
	t.Parallel()

	httpCfg := authoidc.Config{
		ProviderMap: authoidc.ProviderMap{
			"oidc": {
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				Callback:     "https://console.example/auth/callback",
				Scopes:       []string{"openid", "profile", "email"},
				DiscoveryURL: "https://issuer.example/.well-known/openid-configuration",
			},
		},
	}

	canonicalCfg := authoidc.Config(httpCfg)
	provider := canonicalCfg.ProviderMap["oidc"]

	require.Equal(t, "client-id", provider.ClientID, "expected client id to round-trip")
	require.Equal(t, "https://issuer.example/.well-known/openid-configuration", provider.DiscoveryURL, "expected discovery URL to round-trip")
}

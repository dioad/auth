package oidc

import (
	"testing"

	authoidc "github.com/dioad/auth/oidc"
)

func TestConfigAliases_CompatibleWithCanonicalOIDCConfig(t *testing.T) {
	t.Parallel()

	httpCfg := Config{
		ProviderMap: ProviderMap{
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

	if provider.ClientID != "client-id" {
		t.Fatalf("expected client id to round-trip, got %q", provider.ClientID)
	}
	if provider.DiscoveryURL != "https://issuer.example/.well-known/openid-configuration" {
		t.Fatalf("expected discovery URL to round-trip, got %q", provider.DiscoveryURL)
	}
}

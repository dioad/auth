package github

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveAccessToken(t *testing.T) {
	t.Run("StaticToken", func(t *testing.T) {
		cfg := ClientConfig{
			AccessToken: "static-token",
		}
		token, err := ResolveAccessToken(cfg)
		assert.NoError(t, err)
		assert.Equal(t, "static-token", token)
	})

	t.Run("EnvironmentToken", func(t *testing.T) {
		os.Setenv("GH_TOKEN", "env-token")
		defer os.Unsetenv("GH_TOKEN")

		cfg := ClientConfig{
			EnableAccessTokenFromEnvironment: true,
			EnvironmentVariableName:          "GH_TOKEN",
		}
		token, err := ResolveAccessToken(cfg)
		assert.NoError(t, err)
		assert.Equal(t, "env-token", token)
	})
}

func TestFromMap(t *testing.T) {
	m := map[string]any{
		"client-id":     "id123",
		"client-secret": "secret123",
	}
	cfg := FromMap(m)
	assert.Equal(t, "id123", cfg.ClientID)
	assert.Equal(t, "secret123", cfg.ClientSecret)
}

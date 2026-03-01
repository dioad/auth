package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type stubClock struct {
	now time.Time
}

func (c stubClock) Now() time.Time {
	return c.now
}

func TestTokenSourceGithubActionsAlias(t *testing.T) {
	cfg := ClientConfig{
		EndpointConfig: EndpointConfig{Type: "githubactions", URL: "https://token.actions.githubusercontent.com"},
		Audience:       "api://aud",
	}

	source, err := NewTokenSourceFromConfigWithFactories(cfg, nil, nil, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, source)
}

func TestTokenSourceFromFile(t *testing.T) {
	tokenPath := t.TempDir() + "/token.json"
	require.NoError(t, SaveTokenToFile(&oauth2.Token{
		AccessToken: "abc123",
		Expiry:      time.Now().Add(-time.Hour), // ensure we still return even if expired and no refresh token
	}, tokenPath))

	cfg := ClientConfig{TokenFile: tokenPath}

	source, err := NewTokenSourceFromConfigWithFactories(cfg, nil, nil, stubClock{now: time.Now()}, context.Background())
	require.NoError(t, err)
	require.NotNil(t, source)

	token, err := source.Token()
	require.NoError(t, err)
	require.Equal(t, "abc123", token.AccessToken)
}

func TestTokenSourceCustomFactory(t *testing.T) {
	cfg := ClientConfig{
		EndpointConfig: EndpointConfig{Type: "custom"},
	}

	factories := map[string]TokenSourceFactory{
		"custom": func(cfg ClientConfig) (oauth2.TokenSource, error) {
			return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "custom"}), nil
		},
	}

	source, err := NewTokenSourceFromConfigWithFactories(cfg, factories, nil, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, source)

	token, err := source.Token()
	require.NoError(t, err)
	require.Equal(t, "custom", token.AccessToken)
}

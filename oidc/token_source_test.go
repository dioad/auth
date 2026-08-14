package oidc

import (
	"context"
	"errors"
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

type flakyTokenSource struct {
	failuresRemaining int
	token             *oauth2.Token
}

func (s *flakyTokenSource) Token() (*oauth2.Token, error) {
	if s.failuresRemaining > 0 {
		s.failuresRemaining--
		return nil, errors.New("token not available yet")
	}
	return s.token, nil
}

func TestWaitingTokenSource_IndefiniteTimeoutSucceedsAfterRetries(t *testing.T) {
	source := &flakyTokenSource{failuresRemaining: 3, token: &oauth2.Token{AccessToken: "eventual"}}
	waiting := NewWaitingTokenSource(context.Background(), source, time.Millisecond, 0)

	token, err := waiting.Token()
	require.NoError(t, err)
	require.Equal(t, "eventual", token.AccessToken)
}

func TestWaitingTokenSource_IndefiniteTimeoutStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &flakyTokenSource{failuresRemaining: 1 << 30} // never succeeds
	waiting := NewWaitingTokenSource(ctx, source, time.Millisecond, 0)

	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	_, err := waiting.Token()
	require.ErrorIs(t, err, context.Canceled)
}

func TestWaitingTokenSource_PositiveTimeoutStillExpires(t *testing.T) {
	source := &flakyTokenSource{failuresRemaining: 1 << 30} // never succeeds
	waiting := NewWaitingTokenSource(context.Background(), source, time.Millisecond, 5*time.Millisecond)

	_, err := waiting.Token()
	require.ErrorContains(t, err, "timeout waiting for token")
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

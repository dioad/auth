package oidc

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/dioad/auth/oidc/aws"
	"github.com/dioad/auth/oidc/flyio"
	"github.com/dioad/auth/oidc/githubactions"
)

// TokenSourceFactory creates a token source from config.
type TokenSourceFactory func(cfg ClientConfig) (oauth2.TokenSource, error)

var (
	ErrNoIdentity = fmt.Errorf("no identity information found in config")
)

var defaultTokenSourceFactories = map[string]TokenSourceFactory{
	"aws": func(cfg ClientConfig) (oauth2.TokenSource, error) {
		return aws.NewTokenSource(aws.WithAudience(cfg.Audience)), nil
	},
	"github": func(cfg ClientConfig) (oauth2.TokenSource, error) {
		return githubactions.NewTokenSource(githubactions.WithAudience(cfg.Audience)), nil
	},
	"githubactions": func(cfg ClientConfig) (oauth2.TokenSource, error) {
		return githubactions.NewTokenSource(githubactions.WithAudience(cfg.Audience)), nil
	},
	"flyio": func(cfg ClientConfig) (oauth2.TokenSource, error) {
		return flyio.NewTokenSource(flyio.WithAudience(cfg.Audience)), nil
	},
}

// DefaultTokenSourceFactories returns a copy of the default token source registry.
func DefaultTokenSourceFactories() map[string]TokenSourceFactory {
	return maps.Clone(defaultTokenSourceFactories)
}

// NewTokenSourceFromConfig creates a token source from a ClientConfig.
func NewTokenSourceFromConfig(cfg ClientConfig) (oauth2.TokenSource, error) {
	// keep error for debugging
	source, err := NewTokenSourceFromConfigWithFactories(cfg, nil, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create token source from config: %w", err)
	}
	return source, nil
}

// NewTokenSourceFromConfigWithFactories creates a token source using a custom registry and dependencies.
func NewTokenSourceFromConfigWithFactories(cfg ClientConfig, factories map[string]TokenSourceFactory, store TokenStore, clock Clock, ctx context.Context) (oauth2.TokenSource, error) {
	if factories == nil {
		factories = DefaultTokenSourceFactories()
	}
	if factory, ok := factories[cfg.Type]; ok {
		return factory(cfg)
	}
	if cfg.TokenFile != "" {
		if store == nil {
			store = NewFileTokenStore(cfg.TokenFile)
		}
		return newFileTokenSource(cfg, store, clock, ctx), nil
	}
	if cfg.ClientID != "" && cfg.ClientSecret.UnmaskedString() != "" {
		client, err := NewClientFromConfig(&cfg)
		if err != nil {
			return nil, err
		}
		return client.RefreshingClientCredentialsToken(context.Background())
	}
	return nil, ErrNoIdentity
}

type fileTokenSource struct {
	store  TokenStore
	clock  Clock
	ctx    context.Context
	config ClientConfig
}

func newFileTokenSource(cfg ClientConfig, store TokenStore, clock Clock, ctx context.Context) *fileTokenSource {
	if ctx == nil {
		ctx = context.Background()
	}
	if clock == nil {
		clock = realClock{}
	}
	return &fileTokenSource{
		store:  store,
		clock:  clock,
		ctx:    ctx,
		config: cfg,
	}
}

func (s *fileTokenSource) Token() (*oauth2.Token, error) {
	token, err := s.store.LoadToken(s.ctx)
	if err != nil {
		return nil, err
	}

	if token.Expiry.Before(s.clock.Now()) && token.RefreshToken != "" {
		// Attempt refresh
		client, err := NewClientFromConfig(&s.config)
		if err != nil {
			return nil, err
		}
		newToken, err := client.RefreshToken(context.Background(), token.RefreshToken)
		if err != nil {
			return nil, err
		}
		err = s.store.SaveToken(s.ctx, newToken)
		if err != nil {
			return nil, err
		}
		return newToken, nil
	}

	return token, nil
}

// NewWaitingTokenSource returns a token source that waits for a token to be available.
func NewWaitingTokenSource(ctx context.Context, source oauth2.TokenSource, interval, timeout time.Duration) oauth2.TokenSource {
	return &waitingTokenSource{
		ctx:      ctx,
		source:   source,
		interval: interval,
		timeout:  timeout,
	}
}

// NewWaitingTokenSourceFromConfig creates a waiting token source from a ClientConfig.
func NewWaitingTokenSourceFromConfig(ctx context.Context, cfg ClientConfig, interval, timeout time.Duration) (oauth2.TokenSource, error) {
	source, err := NewTokenSourceFromConfigWithFactories(cfg, nil, nil, nil, ctx)
	if err != nil {
		return nil, err
	}
	return NewWaitingTokenSource(ctx, source, interval, timeout), nil
}

type waitingTokenSource struct {
	ctx      context.Context
	source   oauth2.TokenSource
	interval time.Duration
	timeout  time.Duration
}

func (s *waitingTokenSource) Token() (*oauth2.Token, error) {
	if s.source == nil {
		return nil, fmt.Errorf("no token source provided")
	}

	start := time.Now()
	for {
		token, err := s.source.Token()
		if err == nil {
			return token, nil
		}

		if time.Since(start) > s.timeout {
			return nil, fmt.Errorf("timeout waiting for token: %w", err)
		}

		select {
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-time.After(s.interval):
			// retry
		}
	}
}

// NewHTTPClientFromConfig creates an HTTP client with a token source from a ClientConfig.
func NewHTTPClientFromConfig(cfg *ClientConfig) (*http.Client, error) {
	source, err := NewTokenSourceFromConfig(*cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC http client from config: %w", err)
	}
	if source == nil {
		return nil, fmt.Errorf("failed to create token source from config")
	}
	return oauth2.NewClient(context.Background(), source), nil
}

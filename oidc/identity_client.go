package oidc

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/dioad/generics"
	"golang.org/x/oauth2"

	"github.com/dioad/net/tls"
)

// DefaultIdentityClientTimeout is the request timeout of clients built by
// NewIdentityClient, unless WithTimeout says otherwise.
const DefaultIdentityClientTimeout = 10 * time.Second

// IdentityClientOption configures NewIdentityClient.
type IdentityClientOption func(*identityClientOptions)

type identityClientOptions struct {
	timeout       time.Duration
	baseTransport *http.Transport
}

// WithTimeout sets the request timeout for calls to the target service and to
// the token endpoint. Zero means no timeout.
func WithTimeout(timeout time.Duration) IdentityClientOption {
	return func(o *identityClientOptions) {
		o.timeout = timeout
	}
}

// WithBaseTransport sets the transport that calls are sent through. It is
// cloned before any TLS configuration is applied, so the caller's transport
// is never modified. The default is a clone of http.DefaultTransport.
func WithBaseTransport(transport *http.Transport) IdentityClientOption {
	return func(o *identityClientOptions) {
		if transport != nil {
			o.baseTransport = transport
		}
	}
}

// NewIdentityClient returns an HTTP client that authenticates as identity
// (OAuth2 client credentials, a platform workload identity, or a token file)
// when identity is set, and a plain client when identity is the zero value.
//
// target configures TLS to the service being called. identity.TLSClient
// configures TLS to the identity provider's discovery and token endpoints. It
// has no effect for the platform identity types "aws", "githubactions" and
// "flyio", which fetch their tokens from the platform rather than a provider
// this client reaches.
//
// Tokens are fetched lazily, on the first request and again when they expire.
// Those fetches keep ctx's values but not its cancellation, so the client
// outlives a ctx that is cancelled once start-up is done.
func NewIdentityClient(ctx context.Context, identity ClientConfig, target tls.ClientConfig, opts ...IdentityClientOption) (*http.Client, error) {
	options := &identityClientOptions{timeout: DefaultIdentityClientTimeout}
	for _, opt := range opts {
		opt(options)
	}
	if options.baseTransport == nil {
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("unexpected type for http.DefaultTransport: %T", http.DefaultTransport)
		}
		options.baseTransport = defaultTransport
	}

	targetTransport, err := transportWithTLS(options.baseTransport, target)
	if err != nil {
		return nil, fmt.Errorf("failed to create target TLS config: %w", err)
	}

	if generics.IsZeroValue(identity) {
		return &http.Client{Transport: targetTransport, Timeout: options.timeout}, nil
	}

	identityTransport, err := transportWithTLS(options.baseTransport, identity.TLSClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity TLS config: %w", err)
	}
	identityClient := &http.Client{Transport: identityTransport, Timeout: options.timeout}

	tokenSource, err := newTokenSourceFromConfig(context.WithoutCancel(ctx), identity, nil, nil, nil, identityClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create token source: %w", err)
	}

	return &http.Client{
		Transport: &oauth2.Transport{
			Base:   targetTransport,
			Source: oauth2.ReuseTokenSource(nil, tokenSource),
		},
		Timeout: options.timeout,
	}, nil
}

// transportWithTLS returns a clone of base that uses cfg for TLS. A zero cfg
// keeps base's own TLS settings.
func transportWithTLS(base *http.Transport, cfg tls.ClientConfig) (*http.Transport, error) {
	tlsConfig, err := tls.NewClientTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	transport := base.Clone()
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}
	return transport, nil
}

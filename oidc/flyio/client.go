// Package flyio provides an OIDC token source and principal extraction for
// Fly.io Machines, using tokens issued via Fly.io's local metadata socket.
package flyio

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"golang.org/x/oauth2"
)

// NewUnixSocketClient returns an *http.Client that dials the Unix socket at
// path regardless of the request's network or address.
func NewUnixSocketClient(path string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}
}

// NewHTTPClient creates an *http.Client that authenticates with a Fly.io
// OIDC token, fetching one immediately to fail fast on misconfiguration.
func NewHTTPClient(ctx context.Context, opts ...Opt) (*http.Client, error) {
	ts := NewTokenSource(opts...)
	_, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("error getting flyio token: %w", err)
	}

	rts := oauth2.ReuseTokenSource(nil, ts)

	return oauth2.NewClient(ctx, rts), nil
}

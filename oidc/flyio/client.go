package flyio

import (
	"context"
	"net"
	"net/http"

	"golang.org/x/oauth2"
)

func NewUnixSocketClient(path string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", path)
			},
		},
	}
}

func NewHTTPClient(ctx context.Context, opts ...Opt) *http.Client {
	ts := NewTokenSource(opts...)
	rts := oauth2.ReuseTokenSource(nil, ts)

	return oauth2.NewClient(ctx, rts)
}

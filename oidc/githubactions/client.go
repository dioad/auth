package githubactions

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// NewHTTPClient creates an HTTP client configured with GitHub Actions OIDC authentication
func NewHTTPClient(ctx context.Context, opts ...Opt) *http.Client {
	ts := NewTokenSource(opts...)
	rts := oauth2.ReuseTokenSource(nil, ts)

	return oauth2.NewClient(ctx, rts)
}

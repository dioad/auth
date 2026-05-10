package githubactions

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// NewHTTPClient creates an HTTP client configured with GitHub Actions OIDC authentication.
func NewHTTPClient(ctx context.Context, opts ...Opt) (*http.Client, error) {
	ts := NewTokenSource(opts...)
	_, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("error getting token: %w", err)
	}

	rts := oauth2.ReuseTokenSource(nil, ts)

	return oauth2.NewClient(ctx, rts), nil
}

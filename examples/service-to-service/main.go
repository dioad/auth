// Command main calls another service as this service's own identity, using
// oidc.NewIdentityClient.
//
// The identity is a workload identity from the platform the program runs on
// (GitHub Actions, Fly.io or AWS), or an OAuth2 client for the client
// credentials grant. With no identity configured it makes the call without
// credentials, which suits local development. See the README.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/dioad/auth/oidc"
	"github.com/dioad/net/tls"
	"github.com/dioad/util"
)

const requestTimeout = 15 * time.Second

func main() {
	logger := zerolog.New(os.Stderr).With().Timestamp().Str("component", "service-to-service").Logger()

	if err := run(logger); err != nil {
		logger.Error().Err(err).Msg("service-to-service failed")
		os.Exit(1)
	}
}

func run(logger zerolog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		return errors.New("set TARGET_URL to the URL to call")
	}

	// NewIdentityClient fetches tokens lazily, on the first request and again
	// when they expire, so building the client does no network I/O.
	client, err := oidc.NewIdentityClient(ctx, identityFromEnv(), tls.ClientConfig{}, oidc.WithTimeout(requestTimeout))
	if err != nil {
		return fmt.Errorf("creating identity client: %w", err)
	}

	// The URL is this program's configuration, not untrusted input.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil) // #nosec G704 -- see above
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	resp, err := client.Do(req) // #nosec G704 -- see above
	if err != nil {
		return fmt.Errorf("calling %s: %w", targetURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	logger.Info().Int("status", resp.StatusCode).Msg("called service")
	fmt.Printf("%s\n", body)

	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("%s answered %s", targetURL, resp.Status)
	}
	return nil
}

// identityFromEnv selects the identity this service authenticates as.
//
//   - IDENTITY_TYPE is "githubactions", "flyio" or "aws" for a workload
//     identity from the platform. IDENTITY_AUDIENCE is the audience the target
//     service expects.
//   - IDENTITY_TOKEN_FILE names a file holding a token, which is refreshed
//     from it when it expires. scripts/gen_smoke_token.py writes one.
//   - Otherwise IDENTITY_ISSUER, IDENTITY_CLIENT_ID and IDENTITY_CLIENT_SECRET
//     select an OAuth2 client for the client credentials grant.
//   - With neither, the zero identity is returned and calls carry no token.
func identityFromEnv() oidc.ClientConfig {
	if platform := os.Getenv("IDENTITY_TYPE"); platform != "" {
		return oidc.ClientConfig{
			Type:     platform,
			Audience: os.Getenv("IDENTITY_AUDIENCE"),
		}
	}

	if tokenFile := os.Getenv("IDENTITY_TOKEN_FILE"); tokenFile != "" {
		return oidc.ClientConfig{TokenFile: tokenFile}
	}

	issuer := os.Getenv("IDENTITY_ISSUER")
	if issuer == "" {
		return oidc.ClientConfig{}
	}
	return oidc.ClientConfig{
		URL:          issuer,
		ClientID:     os.Getenv("IDENTITY_CLIENT_ID"),
		ClientSecret: *util.NewMaskedString(os.Getenv("IDENTITY_CLIENT_SECRET")),
	}
}

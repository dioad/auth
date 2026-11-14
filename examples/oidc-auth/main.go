// Command main demonstrates wrapping an HTTP server with OIDC token
// validation middleware, accepting GitHub Actions OIDC tokens.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	authserver "github.com/dioad/auth/http/server"
	"github.com/dioad/auth/oidc"

	diohttp "github.com/dioad/net/http"
)

const shutdownTimeout = 10 * time.Second

func main() {
	logger := zerolog.New(os.Stderr).With().Timestamp().Str("component", "oidc-auth").Logger()

	if err := run(logger); err != nil {
		logger.Error().Err(err).Msg("oidc-auth failed")
		os.Exit(1)
	}
}

func run(logger zerolog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	validatorConfig := oidc.ValidatorConfig{
		Type:      oidc.ProviderTypeGitHubActions,
		URL:       "https://token.actions.githubusercontent.com",
		Audiences: []string{envOr("OIDC_AUDIENCE", "https://github.com/my-org")},
		Issuer:    "https://token.actions.githubusercontent.com",
	}

	listenAddr := envOr("LISTEN_ADDR", "127.0.0.1:8080")

	// The validator is global middleware: it checks the bearer token in the
	// Authorization header of every request, and rejects a request without
	// one. It does not read cookies.
	srv := diohttp.NewServer(
		diohttp.Config{ListenAddress: listenAddr},
		diohttp.WithLogger(logger),
		authserver.WithOAuth2Validator([]oidc.ValidatorConfig{validatorConfig}),
	)
	srv.AddHandlerFunc("GET /secure", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "Hello, authenticated caller!")
	})

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", listenAddr, err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	logger.Info().Str("address", ln.Addr().String()).Msg("listening for GitHub Actions OIDC tokens")

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	logger.Info().Msg("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

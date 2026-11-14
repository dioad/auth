// Command main is a minimal single-page app and API protected by a browser
// session: OIDC login, encrypted session cookies and a backend-for-frontend.
//
// See the README for configuration.
package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/dioad/auth"
	"github.com/dioad/auth/claimrolemapping"
	"github.com/dioad/auth/http/browsersession"
	"github.com/dioad/auth/http/middleware"
	oidcmw "github.com/dioad/auth/http/middleware/oidc"
	"github.com/dioad/auth/http/server"
	"github.com/dioad/auth/oidc"

	diohttp "github.com/dioad/net/http"
)

//go:embed static
var staticFiles embed.FS

const shutdownTimeout = 10 * time.Second

func main() {
	logger := zerolog.New(os.Stderr).With().Timestamp().Str("component", "browser-session").Logger()

	if err := run(logger); err != nil {
		logger.Error().Err(err).Msg("browser-session failed")
		os.Exit(1)
	}
}

func run(logger zerolog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := configFromEnv()
	if err != nil {
		return err
	}

	// The API behind the session validates the session's access token like
	// any bearer token, then extracts a principal from it.
	validate, err := server.OAuth2ValidatorHandler([]oidc.ValidatorConfig{{
		URL:       cfg.OIDC.Issuer,
		Issuer:    cfg.OIDC.Issuer,
		Audiences: []string{cfg.OIDC.ClientID},
	}})
	if err != nil {
		return fmt.Errorf("creating JWT validator: %w", err)
	}
	extractor := claimrolemapping.BuildPrincipalExtractor(claimrolemapping.ExtractorConfig{}, logger)
	api := http.NewServeMux()
	api.Handle("GET /me", validate(middleware.PrincipalExtractionHandler(extractor)(http.HandlerFunc(me))))

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return err
	}
	app, err := browsersession.NewApp(cfg, api, staticFS)
	if err != nil {
		return fmt.Errorf("creating browser session app: %w", err)
	}

	listenAddr := envOr("LISTEN_ADDR", "127.0.0.1:8080")
	srv := diohttp.NewServer(diohttp.Config{ListenAddress: listenAddr}, diohttp.WithLogger(logger))
	srv.AddHandler("/auth/", http.StripPrefix("/auth", app.Auth))
	srv.AddHandler("/api/", http.StripPrefix("/api", app.API))
	srv.AddHandler("/", app.UI)

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", listenAddr, err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	logger.Info().Str("address", ln.Addr().String()).Msg("listening")

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

func me(w http.ResponseWriter, r *http.Request) {
	principal := auth.PrincipalContextFromContext(r.Context())
	_, _ = fmt.Fprintf(w, "Signed in as %s\n", principal.ID)
}

func configFromEnv() (browsersession.Config, error) {
	cfg := browsersession.Config{
		OIDC: oidcmw.BrowserConfig{
			Issuer:       os.Getenv("OIDC_ISSUER"),
			ClientID:     os.Getenv("OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
			RedirectURI:  envOr("OIDC_REDIRECT_URI", "http://127.0.0.1:8080/auth/callback"),
			LoginPath:    "/auth/login",
			// Required. Browsers treat 127.0.0.1 as a secure context, so a
			// Secure cookie still works over plain HTTP on localhost.
			CookieSecure: true,
		},
		CookieEncryptionKey: os.Getenv("COOKIE_ENCRYPTION_KEY"),
	}
	if err := cfg.OIDC.Validate(); err != nil {
		return cfg, fmt.Errorf("%w (set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and COOKIE_ENCRYPTION_KEY)", err)
	}
	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Command main is an API protected by JWT validation, principal extraction and
// a role check.
//
// It runs against either a real OIDC issuer (ISSUER and AUDIENCE) or, for
// local development and CI, a shared secret (HMAC_SECRET). See the README.
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

	"github.com/dioad/auth"
	"github.com/dioad/auth/authz"
	"github.com/dioad/auth/claimrolemapping"
	"github.com/dioad/auth/http/middleware"
	"github.com/dioad/auth/http/server"
	"github.com/dioad/auth/oidc"

	diohttp "github.com/dioad/net/http"
)

const shutdownTimeout = 10 * time.Second

func main() {
	logger := zerolog.New(os.Stderr).With().Timestamp().Str("component", "api-auth").Logger()

	if err := run(logger); err != nil {
		logger.Error().Err(err).Msg("api-auth failed")
		os.Exit(1)
	}
}

func run(logger zerolog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	validators, err := validatorConfigFromEnv()
	if err != nil {
		return err
	}
	validate, err := server.OAuth2ValidatorHandler(validators)
	if err != nil {
		return fmt.Errorf("creating JWT validator: %w", err)
	}

	// Principal extraction turns the validated token into a principal with
	// roles. A group in the token's "groups" claim is a role as it stands, so
	// a token in "api-admins" has that role without any mapping. A
	// claim-role-mapping rule can add roles from other claims; this one
	// grants "api-admins" to a named user as well.
	extractor := claimrolemapping.BuildPrincipalExtractor(claimrolemapping.ExtractorConfig{
		ClaimRoleMappings: []claimrolemapping.ClaimRoleMappingConfig{
			{Source: claimrolemapping.SourceOIDC, Claims: map[string]string{"username": "root"}, Role: "api-admins"},
		},
	}, logger)

	// The authorizer maps roles to capabilities.
	authorizer := authz.NewRoleAuthorizer(authz.PolicyMetadata{
		RoleCapabilities: map[authz.Role][]authz.Capability{
			"api-admins": {authz.Permission("admin", "read")},
		},
	})

	listenAddr := envOr("LISTEN_ADDR", "127.0.0.1:8080")
	srv := diohttp.NewServer(diohttp.Config{ListenAddress: listenAddr}, diohttp.WithLogger(logger))
	srv.AddHandler("GET /whoami", protect(validate, extractor, whoami))
	srv.AddHandler("GET /admin", protect(validate, extractor, admin(authorizer)))

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

// protect wraps handler with token validation, then principal extraction.
func protect(validate diohttp.Middleware, extractor auth.PrincipalExtractor, handler http.HandlerFunc) http.Handler {
	return validate(middleware.PrincipalExtractionHandler(extractor)(handler))
}

func whoami(w http.ResponseWriter, r *http.Request) {
	principal := auth.PrincipalContextFromContext(r.Context())
	_, _ = fmt.Fprintf(w, "%s (%s) roles=%v\n", principal.ID, principal.Source, principal.Roles)
}

// admin answers only to principals whose roles grant admin:read.
func admin(authorizer authz.Authorizer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal := auth.PrincipalContextFromContext(r.Context())
		if err := authz.Check(r.Context(), authorizer, principal, authz.Permission("admin", "read")); err != nil {
			status := http.StatusForbidden
			if errors.Is(err, authz.ErrUnauthorized) {
				status = http.StatusUnauthorized
			}
			http.Error(w, http.StatusText(status), status)
			return
		}
		_, _ = fmt.Fprintln(w, "welcome, admin")
	}
}

// validatorConfigFromEnv selects how tokens are validated.
func validatorConfigFromEnv() ([]oidc.ValidatorConfig, error) {
	audience := envOr("AUDIENCE", "api-auth")

	if secret := os.Getenv("HMAC_SECRET"); secret != "" {
		// A shared secret is for local development and CI only.
		return []oidc.ValidatorConfig{{
			HMACSecret:        secret,
			AllowInsecureHMAC: true,
			Audiences:         []string{audience},
		}}, nil
	}

	issuer := os.Getenv("ISSUER")
	if issuer == "" {
		return nil, errors.New("set ISSUER (and AUDIENCE) to validate tokens from an OIDC issuer, or HMAC_SECRET for local development")
	}
	return []oidc.ValidatorConfig{{
		URL:       issuer,
		Issuer:    issuer,
		Audiences: []string{audience},
	}}, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

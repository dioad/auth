package http

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/dioad/generics"

	"github.com/dioad/auth/http/basic"
	"github.com/dioad/auth/http/github"
	"github.com/dioad/auth/http/hmac"
	"github.com/dioad/auth/http/middleware/jwt"
	"github.com/dioad/auth/http/middleware/oidc"
	authjwt "github.com/dioad/auth/jwt"
	authoidc "github.com/dioad/auth/oidc"
)

// LoginRoutable is implemented by auth middlewares that need additional HTTP
// routes registered beyond the Wrap middleware chain (currently only OIDC's
// login/callback/logout flow).
type LoginRoutable interface {
	AuthStart() http.HandlerFunc
	Callback() http.HandlerFunc
	Logout() http.HandlerFunc
	LoginPath() string
	CallbackPath() string
	LogoutPath() string
}

// Handler describes an HTTP authentication handler.
type Handler struct {
	Config     ServerConfig
	middleware Middleware
}

// LoginRoutes returns h's concrete login-routing methods, if its underlying
// middleware implements LoginRoutable.
func (h *Handler) LoginRoutes() (LoginRoutable, bool) {
	lr, ok := h.middleware.(LoginRoutable)
	return lr, ok
}

// NewHandler creates a new authentication handler from the provided configuration.
func NewHandler(cfg *ServerConfig) (*Handler, error) {
	mw, err := resolveAuthHandler(cfg)
	if err != nil {
		return nil, err
	}
	return &Handler{
		Config:     *cfg,
		middleware: mw,
	}, nil
}

func resolveAuthHandler(cfg *ServerConfig) (Middleware, error) {
	if cfg.Type != "" {
		return resolveAuthHandlerByType(cfg)
	}
	// Legacy: detect handler from whichever config sub-struct is non-zero.
	if !generics.IsZeroValue(cfg.GitHubAuthConfig) {
		return github.NewHandler(cfg.GitHubAuthConfig), nil
	} else if !generics.IsZeroValue(cfg.BasicAuthConfig) {
		return basic.NewHandler(cfg.BasicAuthConfig)
	} else if !generics.IsZeroValue(cfg.HMACAuthConfig) {
		return hmac.NewHandler(cfg.HMACAuthConfig), nil
	} else if !generics.IsZeroValue(cfg.JWTAuthConfig) {
		validator, err := authjwt.NewValidatorFromConfig(&cfg.JWTAuthConfig)
		if err != nil {
			return nil, err
		}
		return jwt.NewHandler(validator, "auth_token").WithRequireToken(true), nil
	} else if !generics.IsZeroValue(cfg.OIDCAuthConfig) {
		return resolveOIDCHandler(&cfg.OIDCAuthConfig)
	}
	return nil, nil
}

func resolveAuthHandlerByType(cfg *ServerConfig) (Middleware, error) {
	switch cfg.Type {
	case "github":
		return github.NewHandler(cfg.GitHubAuthConfig), nil
	case "basic":
		return basic.NewHandler(cfg.BasicAuthConfig)
	case "hmac":
		return hmac.NewHandler(cfg.HMACAuthConfig), nil
	case "jwt":
		validator, err := authjwt.NewValidatorFromConfig(&cfg.JWTAuthConfig)
		if err != nil {
			return nil, err
		}
		return jwt.NewHandler(validator, "auth_token").WithRequireToken(true), nil
	case "oidc":
		return resolveOIDCHandler(&cfg.OIDCAuthConfig)
	default:
		return nil, fmt.Errorf("unknown auth type %q — use one of: github, basic, hmac, jwt, oidc", cfg.Type)
	}
}

// resolveOIDCHandler builds the OIDC middleware handler for a single-provider
// "type: oidc" gate. It fails fast at construction time (server startup) when
// RedirectURI is missing or unparseable, rather than accepting the config
// silently and only discovering the broken callback per-request.
func resolveOIDCHandler(cfg *OIDCServerConfig) (Middleware, error) {
	client, err := authoidc.NewClientFromConfig(&cfg.ClientConfig)
	if err != nil {
		return nil, err
	}

	if cfg.RedirectURI == "" {
		return nil, fmt.Errorf("oidc auth: redirect-uri is required to complete a login")
	}
	u, err := url.Parse(cfg.RedirectURI)
	if err != nil || u.Path == "" {
		return nil, fmt.Errorf("oidc auth: redirect-uri %q must be a valid absolute URL with a path", cfg.RedirectURI)
	}

	return oidc.NewHandler(client, cfg.OIDCConfig), nil
}

// Wrap wraps an HTTP handler with authentication middleware.
func (h *Handler) Wrap(handler http.Handler) http.Handler {
	if h.middleware == nil {
		return handler
	}

	return h.middleware.Wrap(handler)
}

// HandlerFunc creates an authentication-wrapped HTTP handler function from the provided configuration.
func HandlerFunc(cfg *ServerConfig, origHandler http.HandlerFunc) (http.HandlerFunc, error) {
	h, err := NewHandler(cfg)
	if err != nil {
		return nil, err
	}
	return h.Wrap(origHandler).ServeHTTP, nil
}

// NullHandler is a handler that passes through to the next handler without authentication.
func NullHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	}
}

// MultiAuthnHandlerFunc creates a handler function that supports multiple authentication providers.
func MultiAuthnHandlerFunc(cfg *ServerConfig, origHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var err error
		for _, provider := range cfg.Providers {
			var a Authenticator
			switch provider {
			case "github":
				a = github.NewHandler(cfg.GitHubAuthConfig)
			case "basic":
				a, err = basic.NewHandler(cfg.BasicAuthConfig)
				if err != nil {
					continue
				}
			case "hmac":
				a = hmac.NewHandler(cfg.HMACAuthConfig)
			default:
				continue
			}

			ctx, err = a.AuthRequest(r)
			if err == nil {
				r = r.WithContext(ctx)
				break
			}
		}

		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		origHandler.ServeHTTP(w, r)
	}
}

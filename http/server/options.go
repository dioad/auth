// Package server provides auth-specific ServerOption factories for github.com/dioad/net/http servers.
package server

import (
	"net/http"

	nethttp "github.com/dioad/net/http"

	authhttp "github.com/dioad/auth/http"
	"github.com/dioad/auth/http/middleware/jwt"
	authjwt "github.com/dioad/auth/jwt"
	"github.com/dioad/auth/oidc"
)

// OAuth2ValidatorHandler returns a middleware that validates OAuth2 tokens using the provided configurations.
func OAuth2ValidatorHandler(v []oidc.ValidatorConfig) (nethttp.Middleware, error) {
	var validators []authjwt.TokenValidator
	for _, cfg := range v {
		validator, err := oidc.NewValidatorFromConfig(&cfg)
		if err != nil {
			return nil, err
		}
		validators = append(validators, validator)
	}

	multiValidator := &authjwt.MultiValidator{Validators: validators}
	authHandler := jwt.NewHandler(multiValidator, "auth_token").WithRequireToken(true)

	return func(next http.Handler) http.Handler {
		return authHandler.Wrap(next)
	}, nil
}

// WithOAuth2Validator returns a ServerOption that configures the server to validate OAuth2 tokens.
func WithOAuth2Validator(v []oidc.ValidatorConfig) nethttp.ServerOption {
	return func(s *nethttp.Server) {
		handler, err := OAuth2ValidatorHandler(v)
		if err == nil {
			s.Use(handler)
		} else {
			s.Logger.Fatal().Err(err).Msg("failed to create OAuth2 validator")
		}
	}
}

// WithServerAuth returns a ServerOption that configures the server to use the given authentication configuration.
// When the resolved auth handler needs additional routes beyond the Wrap
// middleware chain (currently only OIDC's login/callback/logout flow), those
// routes are registered on the server's mux automatically.
func WithServerAuth(cfg authhttp.ServerConfig) nethttp.ServerOption {
	return func(s *nethttp.Server) {
		h, err := authhttp.NewHandler(&cfg)
		if err != nil {
			s.Logger.Fatal().Err(err).Msg("error creating auth handler.")
			return
		}
		if lr, ok := h.LoginRoutes(); ok {
			s.AddHandlerFunc(lr.LoginPath(), lr.AuthStart())
			if cb := lr.CallbackPath(); cb != "" {
				s.AddHandlerFunc(cb, lr.Callback())
			}
			if lp := lr.LogoutPath(); lp != "" {
				s.AddHandlerFunc(lp, lr.Logout())
			}
		}
		s.Use(func(next http.Handler) http.Handler {
			return h.Wrap(next)
		})
	}
}

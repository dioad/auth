// Package server provides auth-specific ServerOption factories for github.com/dioad/net/http servers.
package server

import (
	"net/http"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"

	nethttp "github.com/dioad/net/http"

	authhttp "github.com/dioad/auth/http"
	"github.com/dioad/auth/http/middleware/jwt"
	"github.com/dioad/auth/oidc"
)

// ValidatorHandlerOption configures the middleware built by
// OAuth2ValidatorHandler and WithOAuth2Validator.
type ValidatorHandlerOption func(*validatorHandlerOptions)

type validatorHandlerOptions struct {
	cookieName    string
	debug         bool
	validatorOpts []jwtvalidator.Option
}

// WithCookieTokenName also accepts a bearer token from the cookie called
// name. Without it the token is read from the Authorization header only.
//
// Use it only for browser-facing routes. A machine-to-machine API that
// browsers can reach must not accept a cookie credential: that is a CSRF
// risk, and it couples the API to the cookie name of any browser app on the
// same origin.
func WithCookieTokenName(name string) ValidatorHandlerOption {
	return func(o *validatorHandlerOptions) {
		o.cookieName = name
	}
}

// WithValidatorDebug logs the outcome of every token validation through the
// request-scoped logger. See oidc.NewValidatorDebugger.
func WithValidatorDebug() ValidatorHandlerOption {
	return func(o *validatorHandlerOptions) {
		o.debug = true
	}
}

// WithValidatorOptions passes go-jwt-middleware validator options to every
// configured validator, for example validator.WithCustomClaims. They are base
// options: a validator config or provider type that sets the same thing
// overrides them. See oidc.NewMultiValidatorFromConfig.
func WithValidatorOptions(opts ...jwtvalidator.Option) ValidatorHandlerOption {
	return func(o *validatorHandlerOptions) {
		o.validatorOpts = append(o.validatorOpts, opts...)
	}
}

// OAuth2ValidatorHandler returns a middleware that validates OAuth2 bearer
// tokens using the provided configurations. A request without a token is
// rejected with 401.
//
// The token is read from the Authorization header only. Pass
// WithCookieTokenName to also accept it from a cookie.
func OAuth2ValidatorHandler(v []oidc.ValidatorConfig, opts ...ValidatorHandlerOption) (nethttp.Middleware, error) {
	options := &validatorHandlerOptions{}
	for _, opt := range opts {
		opt(options)
	}

	validator, err := oidc.NewMultiValidatorFromConfig(v, options.validatorOpts...)
	if err != nil {
		return nil, err
	}
	if options.debug {
		validator = oidc.NewValidatorDebugger(validator)
	}

	authHandler := jwt.NewHandler(validator, options.cookieName).WithRequireToken(true)

	return func(next http.Handler) http.Handler {
		return authHandler.Wrap(next)
	}, nil
}

// WithOAuth2Validator returns a ServerOption that configures the server to
// validate OAuth2 bearer tokens. See OAuth2ValidatorHandler for opts.
func WithOAuth2Validator(v []oidc.ValidatorConfig, opts ...ValidatorHandlerOption) nethttp.ServerOption {
	return func(s *nethttp.Server) {
		handler, err := OAuth2ValidatorHandler(v, opts...)
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

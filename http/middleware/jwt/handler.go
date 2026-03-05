package jwt

import (
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/rs/zerolog"

	authhttp "github.com/dioad/auth/http/context"
	"github.com/dioad/auth/jwt"
	"github.com/dioad/net/http/json"
)

// Handler handles JWT authentication and sets the authenticated principal in the context.
type Handler struct {
	validator  jwt.TokenValidator
	opts       []jwtmiddleware.Option
	logger     zerolog.Logger
	cookieName string
}

func NewHandler(validator jwt.TokenValidator, cookieName string, logger zerolog.Logger, opts ...jwtmiddleware.Option) *Handler {
	return &Handler{
		validator:  validator,
		cookieName: cookieName,
		logger:     logger,
		opts:       opts,
	}
}

func (h *Handler) Wrap(next http.Handler) http.Handler {
	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		jsr := json.NewResponseWithLogger(w, r, h.logger)
		jsr.UnauthorizedWithMessages("unauthorised", err.Error())
	}

	handlerOpts := append(
		[]jwtmiddleware.Option{
			jwtmiddleware.WithErrorHandler(errorHandler),
			jwtmiddleware.WithTokenExtractor(
				jwtmiddleware.MultiTokenExtractor(
					jwtmiddleware.AuthHeaderTokenExtractor,
					jwtmiddleware.CookieTokenExtractor(h.cookieName),
				),
			),
		},
		h.opts...,
	)

	middleware := jwtmiddleware.New(
		h.validator.ValidateToken,
		handlerOpts...,
	)

	return middleware.CheckJWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// After CheckJWT, the validated claims are in the context.
		// The key is jwtmiddleware.ContextKey{}.
		validatedClaims := r.Context().Value(jwtmiddleware.ContextKey{})
		if validatedClaims != nil {
			// Extract subject from claims.
			// This matches how net/http/auth/jwt/handler.go worked.

			if claims, ok := validatedClaims.(*jwtvalidator.ValidatedClaims); ok {
				if claims.RegisteredClaims.Subject != "" {
					ctx := authhttp.ContextWithAuthenticatedPrincipal(r.Context(), claims.RegisteredClaims.Subject)
					ctx = authhttp.ContextWithAuthenticatedRegisteredClaims(ctx, claims.RegisteredClaims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	}))
}

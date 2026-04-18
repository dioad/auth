package jwt

import (
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/rs/zerolog"

	"github.com/auth0/go-jwt-middleware/v3/core"
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

	extractor := jwtmiddleware.MultiTokenExtractor(
		jwtmiddleware.AuthHeaderTokenExtractor,
		jwtmiddleware.CookieTokenExtractor(h.cookieName),
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extracted, err := extractor(r)
		if err != nil {
			errorHandler(w, r, err)
			return
		}

		if extracted.Token == "" {
			next.ServeHTTP(w, r)
			return
		}

		validatedClaims, err := h.validator.ValidateToken(r.Context(), extracted.Token)
		if err != nil {
			errorHandler(w, r, err)
			return
		}

		ctx := core.SetClaims(r.Context(), validatedClaims)

		if claims, ok := validatedClaims.(*jwtvalidator.ValidatedClaims); ok {
			if claims.RegisteredClaims.Subject != "" {
				ctx = authhttp.ContextWithAuthenticatedPrincipal(ctx, claims.RegisteredClaims.Subject)
				ctx = authhttp.ContextWithAuthenticatedRegisteredClaims(ctx, claims.RegisteredClaims)
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

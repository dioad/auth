package jwt

import (
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/rs/zerolog"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"github.com/dioad/net/http/json"

	authhttp "github.com/dioad/auth/authctx"
	"github.com/dioad/auth/jwt"
)

// Handler handles JWT authentication and sets the authenticated principal in the context.
type Handler struct {
	validator  jwt.TokenValidator
	opts       []jwtmiddleware.Option
	cookieName string
}

// NewHandler creates a JWT authentication handler. All log output uses the
// request-scoped zerolog context logger so entries automatically carry
// request_id, principal, and other fields injected by upstream middleware.
func NewHandler(validator jwt.TokenValidator, cookieName string, opts ...jwtmiddleware.Option) *Handler {
	return &Handler{
		validator:  validator,
		cookieName: cookieName,
		opts:       opts,
	}
}

func (h *Handler) Wrap(next http.Handler) http.Handler {
	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		jsr := json.NewResponseFromRequest(w, r)
		jsr.Unauthorized(json.LogErr(err))
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
			customClaims, err := jwt.ResolveCustomClaimsMap(claims, extracted.Token)
			if err != nil {
				zerolog.Ctx(r.Context()).Debug().Err(err).Msg("unable to resolve authenticated custom claims")
			} else if len(customClaims) > 0 {
				ctx = authhttp.ContextWithAuthenticatedCustomClaims(ctx, customClaims)
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

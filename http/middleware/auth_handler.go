package middleware

import (
	"errors"
	"net/http"

	"github.com/dioad/net/http/json"
	"github.com/rs/zerolog"

	"github.com/dioad/auth"
)

type principalExtractionHandler struct {
	principalExtractor auth.PrincipalExtractor
	logger             zerolog.Logger
}

func (h *principalExtractionHandler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		response := json.NewResponseWithLogger(w, req, h.logger)
		principalContext, err := h.principalExtractor.ExtractPrincipal(req.Context(), req)
		if err != nil {
			if errors.Is(err, auth.ErrNoPrincipalFound) {
				h.logger.Debug().Err(err).Msg("no principal found")
				response.UnauthorizedWithMessages("unauthorized", "no principal found")
				return
			}

			response.InternalServerErrorWithMessage(err, "error extracting principal")
			return
		}

		if principalContext == nil {
			h.logger.Debug().Msg("no principal found")
			response.UnauthorizedWithMessages("unauthorized", "no principal found")
			return
		}

		// Enrich the request-scoped zerolog logger with principal fields. Because
		// zerolog.Ctx returns a pointer to the shared logger stored by hlog.NewHandler,
		// UpdateContext modifies it in-place and the fields appear in all subsequent
		// log calls for this request — including the deferred hlog.AccessHandler entry.
		zerolog.Ctx(req.Context()).UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("principal", principalContext.ID).Str("auth_source", principalContext.Source)
		})

		ctx := auth.ContextWithPrincipalContext(req.Context(), principalContext)

		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

// PrincipalExtractionHandler returns middleware that extracts principal context,
// enriches request logs with principal fields, and stores the principal in request context.
func PrincipalExtractionHandler(principalExtractor auth.PrincipalExtractor, logger zerolog.Logger) func(next http.Handler) http.Handler {
	return newPrincipalExtractionHandler(principalExtractor, logger).Middleware
}

func newPrincipalExtractionHandler(principalExtractor auth.PrincipalExtractor, logger zerolog.Logger) *principalExtractionHandler {
	return &principalExtractionHandler{
		principalExtractor: principalExtractor,
		logger:             logger,
	}
}

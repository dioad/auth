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
}

func (h *principalExtractionHandler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Use the request-scoped context logger so that error responses carry
		// request_id and any other fields already injected by upstream middleware.
		response := json.NewResponseFromRequest(w, req)
		principalContext, err := h.principalExtractor.ExtractPrincipal(req.Context())
		if err != nil {
			if errors.Is(err, auth.ErrNoPrincipalFound) {
				response.Unauthorized(
					json.PublicMessage("unauthorized"),
					json.LogMessage("no principal found"),
					json.LogErr(err),
				)
				return
			}

			response.InternalServerError(
				json.PublicMessage("error extracting principal"),
				json.LogErr(err),
			)
			return
		}

		if principalContext == nil {
			response.Unauthorized(
				json.PublicMessage("unauthorized"),
				json.LogMessage("no principal found"),
			)
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
// enriches request logs with principal fields (principal, auth_source), and stores
// the principal in the request context.
//
// The middleware uses the request-scoped zerolog context logger for all log output,
// so log entries from this middleware automatically carry request_id and other fields
// injected by upstream middleware (e.g. requestIDMiddleware).
func PrincipalExtractionHandler(principalExtractor auth.PrincipalExtractor) func(next http.Handler) http.Handler {
	return newPrincipalExtractionHandler(principalExtractor).Middleware
}

func newPrincipalExtractionHandler(principalExtractor auth.PrincipalExtractor) *principalExtractionHandler {
	return &principalExtractionHandler{
		principalExtractor: principalExtractor,
	}
}

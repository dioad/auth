// Package principal provides principal-based authorization middleware.
package principal

import (
	stdctx "context"
	"fmt"
	"net/http"

	authhttp "github.com/dioad/auth/http/context"

	"github.com/dioad/net/authz"
)

// HandlerFunc creates a principal-based authorization-wrapped HTTP handler function.
func HandlerFunc(cfg authz.PrincipalACLConfig, next http.Handler) http.HandlerFunc {
	h := NewHandler(cfg)
	return h.Wrap(next).ServeHTTP
}

// Handler implements principal-based authorization for HTTP servers.
type Handler struct {
	Config authz.PrincipalACLConfig
}

// NewHandler creates a new principal-based authorization handler.
func NewHandler(cfg authz.PrincipalACLConfig) *Handler {
	return &Handler{Config: cfg}
}

// AuthRequest checks if the authenticated principal in the request context is authorized.
func (h *Handler) AuthRequest(r *http.Request) (stdctx.Context, error) {
	principal, ok := authhttp.AuthenticatedPrincipalFromContext(r.Context())

	if !ok {
		return r.Context(), fmt.Errorf("no principal found in context")
	}

	userAuthorised := authz.IsPrincipalAuthorised(
		principal,
		h.Config.AllowList,
		h.Config.DenyList)

	if !userAuthorised {
		return r.Context(), fmt.Errorf("user %s is not authorised", principal)
	}
	return r.Context(), nil
}

// Wrap wraps the given handler with principal-based authorization.
func (h *Handler) Wrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := h.AuthRequest(r)

		if err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Package principal provides principal-based authorization middleware.
package principal

import (
	stdctx "context"
	"errors"
	"fmt"
	"net/http"

	authhttp "github.com/dioad/auth/authctx"
	authauthz "github.com/dioad/auth/authz"

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
		return r.Context(), authauthz.ErrUnauthorized
	}

	if !authz.IsPrincipalAuthorised(principal, h.Config.AllowList, h.Config.DenyList) {
		return r.Context(), fmt.Errorf("user %s: %w", principal, authauthz.ErrForbidden)
	}
	return r.Context(), nil
}

// authErrStatus maps an auth error to its HTTP status code.
// ErrUnauthorized (no principal) → 401; all other errors → 403.
func authErrStatus(err error) int {
	if errors.Is(err, authauthz.ErrUnauthorized) {
		return http.StatusUnauthorized
	}
	return http.StatusForbidden
}

// Wrap wraps the given handler with principal-based authorization.
func (h *Handler) Wrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := h.AuthRequest(r)
		if err != nil {
			status := authErrStatus(err)
			http.Error(w, http.StatusText(status), status)
			return
		}
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

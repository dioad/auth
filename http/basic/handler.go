// Package basic provides HTTP Basic authentication middleware and utilities.
package basic

import (
	stdctx "context"
	"fmt"
	"net/http"

	authhttp "github.com/dioad/auth/authctx"
	"github.com/dioad/auth/http/authmw"
)

// Handler implements basic authentication for HTTP servers.
type Handler struct {
	authMap AuthMap
	config  ServerConfig
}

// AuthRequest authenticates an HTTP request using Basic authentication.
func (h *Handler) AuthRequest(r *http.Request) (stdctx.Context, error) {
	reqUser, reqPass, _ := r.BasicAuth()

	if reqUser == "" {
		return r.Context(), fmt.Errorf("no credentials provided")
	}

	authenticated, err := h.authMap.Authenticate(reqUser, reqPass)

	if authenticated {
		return authhttp.ContextWithAuthenticatedPrincipal(r.Context(), reqUser), nil
	}

	if err != nil {
		return r.Context(), err
	}

	return r.Context(), fmt.Errorf("authentication failed")
}

// Wrap wraps an HTTP handler with Basic authentication middleware.
func (h *Handler) Wrap(handler http.Handler) http.Handler {
	return authmw.Wrap(h.AuthRequest, handler, h.writeUnauthorized)
}

// writeUnauthorized sets the WWW-Authenticate challenge header (per the
// configured Realm, or a default) and writes a 401 response.
func (h *Handler) writeUnauthorized(w http.ResponseWriter, _ *http.Request, _ error) {
	if h.config.Realm != "" {
		w.Header().Add("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", h.config.Realm))
	} else {
		w.Header().Add("WWW-Authenticate", "Basic realm=\"Dioad Connect\"")
	}

	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

// NewHandler creates a new Basic authentication handler from the provided configuration.
func NewHandler(cfg ServerConfig) (*Handler, error) {
	// TODO: reload from file every x seconds
	// and figure out a way to handle the err
	authMap, err := LoadBasicAuthFromFile(cfg.HTPasswdFile)

	h := &Handler{
		authMap: authMap,
		config:  cfg,
	}

	return h, err
}

// NewHandlerWithMap creates a new Basic authentication handler using the provided AuthMap.
func NewHandlerWithMap(authMap AuthMap) (*Handler, error) {
	h := &Handler{
		authMap: authMap,
	}

	return h, nil
}

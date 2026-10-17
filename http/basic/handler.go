// Package basic provides HTTP Basic authentication middleware and utilities.
package basic

import (
	stdctx "context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	authhttp "github.com/dioad/auth/authctx"
	"github.com/dioad/auth/http/authmw"
)

// Handler implements basic authentication for HTTP servers. The credential
// map can be replaced at any time via SetAuthMap, safely concurrent with
// in-flight AuthRequest calls - Handler does not need to be rebuilt to pick
// up new or changed credentials.
type Handler struct {
	authMap  atomic.Pointer[AuthMap]
	config   ServerConfig
	throttle *throttle
}

// NewHandler creates a new Basic authentication handler from the provided configuration.
func NewHandler(cfg ServerConfig) (*Handler, error) {
	authMap, err := LoadBasicAuthFromFile(cfg.HTPasswdFile)

	h := newHandler(cfg)
	h.SetAuthMap(authMap)

	return h, err
}

// NewHandlerWithMap creates a new Basic authentication handler using the
// provided AuthMap and configuration (for Realm, used in the
// WWW-Authenticate challenge header). Call h.SetAuthMap later to replace the
// credentials the returned Handler authenticates against, e.g. after a
// credentials file changes on disk.
func NewHandlerWithMap(cfg ServerConfig, authMap AuthMap) (*Handler, error) {
	h := newHandler(cfg)
	h.SetAuthMap(authMap)

	return h, nil
}

func newHandler(cfg ServerConfig) *Handler {
	return &Handler{config: cfg, throttle: newThrottle(cfg.Throttle, time.Now)}
}

// SetAuthMap atomically replaces the credentials Handler authenticates
// against. Safe to call concurrently with in-flight AuthRequest calls.
func (h *Handler) SetAuthMap(m AuthMap) {
	h.authMap.Store(&m)
}

// AuthMap returns the credentials Handler currently authenticates against.
// Safe to call concurrently with SetAuthMap and AuthRequest.
func (h *Handler) AuthMap() AuthMap {
	m := h.authMap.Load()
	if m == nil {
		return nil
	}
	return *m
}

// AuthRequest authenticates an HTTP request using Basic authentication.
//
// Unless disabled in ServerConfig.Throttle, a client address that exceeds the
// failed-login limit is rejected with a *ThrottledError (matching ErrThrottled)
// until its lockout expires, even if it then supplies the right password. A
// request without credentials counts as neither a failure nor a success.
func (h *Handler) AuthRequest(r *http.Request) (stdctx.Context, error) {
	reqUser, reqPass, _ := r.BasicAuth()

	if reqUser == "" {
		return r.Context(), errors.New("no credentials provided")
	}

	key := clientKey(r.RemoteAddr)
	if h.throttle != nil {
		if err := h.throttle.check(key); err != nil {
			return r.Context(), err
		}
	}

	authMap := h.authMap.Load()
	if authMap == nil {
		return r.Context(), errors.New("authentication failed")
	}

	authenticated, err := authMap.Authenticate(reqUser, reqPass)

	if authenticated {
		if h.throttle != nil {
			h.throttle.recordSuccess(key)
		}
		return authhttp.ContextWithAuthenticatedPrincipal(r.Context(), reqUser), nil
	}

	if h.throttle != nil {
		h.throttle.recordFailure(key)
	}

	if err != nil {
		return r.Context(), err
	}

	return r.Context(), errors.New("authentication failed")
}

// Wrap wraps an HTTP handler with Basic authentication middleware.
func (h *Handler) Wrap(handler http.Handler) http.Handler {
	return authmw.Wrap(h.AuthRequest, handler, h.writeUnauthorized)
}

// writeUnauthorized writes 429 with Retry-After for a throttled client.
// Otherwise it sets the WWW-Authenticate challenge header (per the configured
// Realm, or a default) and writes a 401 response.
func (h *Handler) writeUnauthorized(w http.ResponseWriter, _ *http.Request, err error) {
	if throttled, ok := errors.AsType[*ThrottledError](err); ok {
		retryAfter := max(int(math.Ceil(throttled.RetryAfter.Seconds())), 1)
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}

	if h.config.Realm != "" {
		w.Header().Add("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", h.config.Realm))
	} else {
		w.Header().Add("WWW-Authenticate", "Basic realm=\"Dioad Connect\"")
	}

	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

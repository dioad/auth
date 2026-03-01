// Package http provides HTTP authentication utilities and interfaces.
package http

import (
	stdctx "context"
	"net/http"
)

// ClientAuth is an interface for adding authentication to an HTTP request.
type ClientAuth interface {
	AddAuth(*http.Request) error
}

// Middleware is an interface for wrapping an HTTP handler with authentication.
type Middleware interface {
	//	AuthRequest(r *http.Request) (stdctx.Context, error)
	Wrap(http.Handler) http.Handler
}

// Authenticator is an interface for authenticating an HTTP request.
type Authenticator interface {
	AuthRequest(r *http.Request) (stdctx.Context, error)
	// Wrap(http.Handler) http.Handler
}

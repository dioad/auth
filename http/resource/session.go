package resource

import (
	"net/http"

	"github.com/rs/zerolog"

	"github.com/dioad/auth/http/middleware/oidc"
)

// SessionResource is an HTTP resource that manages authentication sessions.
type SessionResource struct {
	AuthHandler *oidc.Handler
	Logger      zerolog.Logger
}

// SessionResourceStatus represents the status of the session resource.
type SessionResourceStatus struct {
	Status string
}

// Handler returns the HTTP handler for the session resource.
func (dr *SessionResource) Handler() http.Handler {
	mux := http.NewServeMux()

	logoutHandler := dr.AuthHandler.Logout()
	callbackHandler := dr.AuthHandler.Callback()
	authStartHandler := dr.AuthHandler.AuthStart()

	// Go 1.22 routing patterns
	mux.HandleFunc("GET /logout", logoutHandler)
	mux.HandleFunc("GET /auth/{provider}/callback", callbackHandler)
	mux.HandleFunc("GET /auth/{provider}", authStartHandler)

	return mux
}

// Status returns the status of the session resource.
func (dr *SessionResource) Status() (any, error) {
	return SessionResourceStatus{
		Status: "OK",
	}, nil
}

// NewSessionResource creates a new session resource with the provided OIDC handler and logger.
func NewSessionResource(handler *oidc.Handler, logger zerolog.Logger) *SessionResource {
	return &SessionResource{
		AuthHandler: handler,
		Logger:      logger,
	}
}

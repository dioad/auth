// Package oidc provides HTTP authentication using OpenID Connect via goth.
package oidc

import (
	stdctx "context"
	"encoding/gob"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/github"
	oidcprovider "github.com/markbates/goth/providers/openidConnect"

	authhttp "github.com/dioad/auth/http/context"
)

// Handler implements OIDC-based authentication using the gothic library.
type Handler struct {
	CookieStore             sessions.Store
	LoginPath               string
	LogoutPath              string
	CallbackDefaultRedirect string
	HomePath                string
}

// SessionData represents the data stored in the session cookie.
type SessionData struct {
	ID        uuid.UUID
	Principal string
	Provider  string
	User      goth.User
}

func init() {
	gob.Register(SessionData{})
	gob.Register(uuid.UUID{})
	gob.Register(goth.User{})
}

// AuthRequest authenticates an HTTP request by checking for a valid OIDC session cookie.
func (h *Handler) AuthRequest(r *http.Request) (stdctx.Context, error) {
	session, err := h.CookieStore.Get(r, SessionCookieName)
	if err != nil {
		return r.Context(), err
	}

	data, ok := session.Values["data"].(SessionData)
	if !ok {
		return r.Context(), fmt.Errorf("missing session data")
	}

	ctx := authhttp.ContextWithAuthenticatedPrincipal(r.Context(), data.Principal)
	ctx = authhttp.ContextWithAuthenticatedCustomClaims(ctx, data.User.RawData)
	ctx = ContextWithOIDCUserInfo(ctx, &data.User)

	return ctx, nil
}

func (h *Handler) handleAuth(w http.ResponseWriter, req *http.Request) (*SessionData, error) {
	session, err := h.CookieStore.Get(req, SessionCookieName)
	if err != nil {
		return nil, err
	}

	if session.IsNew {
		r, _ := h.CookieStore.New(req, PreAuthRefererCookieName)
		r.Values["referer"] = req.URL.String()
		if err = h.CookieStore.Save(req, w, r); err != nil {
			return nil, err
		}

		return nil, nil
	}

	data, ok := session.Values["data"].(SessionData)
	if !ok {
		return nil, fmt.Errorf("missing session data")
	}
	return &data, nil
}

// Middleware returns an HTTP middleware for OIDC authentication.
func (h *Handler) Middleware(next http.Handler) http.Handler {
	return h.AuthWrapper(next.ServeHTTP)
}

// AuthWrapper wraps an HTTP handler function with OIDC authentication.
// If the user is not authenticated, they are redirected to the login path.
func (h *Handler) AuthWrapper(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		sessionData, err := h.handleAuth(w, req)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if sessionData == nil {
			w.Header().Set("Location", h.LoginPath)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}

		ctx := authhttp.ContextWithAuthenticatedPrincipal(req.Context(), sessionData.Principal)
		ctx = ContextWithOIDCUserInfo(ctx, &sessionData.User)

		next.ServeHTTP(w, req.WithContext(ctx))
	}
}

// AuthStart returns an HTTP handler function that starts the OIDC authentication flow.
func (h *Handler) AuthStart() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		gothic.BeginAuthHandler(w, req)
	}
}

func (h *Handler) handleCallback(w http.ResponseWriter, req *http.Request) (string, error) {
	user, err := gothic.CompleteUserAuth(w, req)
	if err != nil {
		return "", err
	}

	session, err := h.CookieStore.New(req, SessionCookieName)
	if err != nil {
		return "", err
	}
	provider := req.PathValue("provider")

	user.RawData = nil

	session.Values["data"] = SessionData{
		ID:        uuid.New(),
		User:      user,
		Principal: user.NickName,
		Provider:  provider,
	}

	if err = h.CookieStore.Save(req, w, session); err != nil {
		return "", err
	}

	redirect := h.HomePath
	r, _ := h.CookieStore.Get(req, PreAuthRefererCookieName)
	if r.Values["referer"] != nil {
		redirect = r.Values["referer"].(string)
		r.Options.MaxAge = -1
		if err = h.CookieStore.Save(req, w, r); err != nil {
			return "", err
		}
	}

	return redirect, nil
}

// Callback handles provider callbacks.
func (h *Handler) Callback() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		redirect, err := h.handleCallback(w, req)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Location", redirect)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}
}

func (*Handler) handleLogout(w http.ResponseWriter, req *http.Request) error {
	session, err := gothic.Store.Get(req, SessionCookieName)
	if err != nil {
		return err
	}
	dataValue, ok := session.Values["data"]
	if !ok {
		return fmt.Errorf("no session data found")
	}
	data := dataValue.(SessionData)

	session.Options.MaxAge = -1
	if err = gothic.Store.Save(req, w, session); err != nil {
		return err
	}

	if data.Provider != "github" {
		if err = gothic.Logout(w, req); err != nil {
			return err
		}
	}
	return nil
}

// LogoutHandler clears authentication state and redirects to login.
func (h *Handler) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		if err := h.handleLogout(w, req); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Location", h.LoginPath)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}
}

// NewHandler configures OIDC providers and returns a handler.
func NewHandler(config Config, store sessions.Store) *Handler {
	gothic.Store = store

	if config.ProviderMap == nil {
		config.ProviderMap = make(map[string]ProviderConfig)
	}

	provider, ok := config.ProviderMap["github"]
	if ok {
		scopes := []string{"read:user", "user:email"}

		if len(provider.Scopes) > 0 {
			scopes = provider.Scopes
		}
		goth.UseProviders(
			github.New(provider.ClientID, provider.ClientSecret, provider.Callback, scopes...),
		)
	}

	provider, ok = config.ProviderMap["oidc"]
	if ok {
		scopes := []string{"openid", "profile", "email", "microprofile-jwt"}

		if len(provider.Scopes) > 0 {
			scopes = provider.Scopes
		}

		oidcProvider, err := oidcprovider.New(provider.ClientID, provider.ClientSecret, provider.Callback, provider.DiscoveryURL, scopes...)
		if err != nil {
			return nil
		}
		goth.UseProviders(
			oidcProvider,
		)
	}

	return &Handler{
		CookieStore: store,
	}
}

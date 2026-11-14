package browsersession

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/rs/zerolog"

	"github.com/dioad/net/http/json"

	oidcmw "github.com/dioad/auth/http/middleware/oidc"
	"github.com/dioad/auth/oidc"
)

// PublicConfig is served by GET /config so the browser app can show which
// identity provider and client it signs in with. Neither value is secret.
type PublicConfig struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
}

// AuthHandler serves the OIDC login flow of a browser session.
type AuthHandler struct {
	// OIDCHandler starts the login flow and owns the state cookie.
	OIDCHandler *oidcmw.Handler
	// OIDCClient exchanges the authorization code and ends the provider
	// session on logout.
	OIDCClient *oidc.Client
	// RedirectURI is the callback URL registered with the provider.
	RedirectURI string
	// PostLoginPath is where the browser is sent after a successful login.
	PostLoginPath string
	// PostLogoutPath is where the browser is sent after logout.
	PostLogoutPath string
	// Cookies stores the session.
	Cookies *CookieSet
	// PublicConfig is the document served by GET /config.
	PublicConfig PublicConfig
}

// Handler returns the routes of the login flow, relative to wherever the
// caller mounts them:
//
//	GET  /login     redirects to the provider (?prompt=create for sign-up)
//	GET  /callback  completes login and sets the session cookies
//	POST /logout    ends the session
//	GET  /config    returns PublicConfig
func (h *AuthHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", h.OIDCHandler.AuthStart())
	mux.HandleFunc("GET /callback", h.callback)
	mux.HandleFunc("POST /logout", h.logout)
	mux.HandleFunc("GET /config", h.config)
	mux.HandleFunc("GET /config/", h.config)
	return mux
}

func (h *AuthHandler) callback(w http.ResponseWriter, r *http.Request) {
	resp := json.NewResponseFromRequest(w, r)
	query := r.URL.Query()

	if errCode := query.Get("error"); errCode != "" {
		resp.BadRequest(json.LogErr(fmt.Errorf("OIDC authorization callback returned error '%v': '%s'", errCode, query.Get("error_description"))))
		return
	}

	code := query.Get("code")
	state := query.Get("state")
	if code == "" {
		resp.BadRequest(json.LogErr(errors.New("OIDC callback missing authorization code")))
		return
	}
	if state == "" {
		resp.BadRequest(json.LogErr(errors.New("OIDC callback missing state")))
		return
	}

	stateCookie := h.OIDCHandler.Config.StateCookie
	stateFromCookie, err := plainCookieValue(r, stateCookie.Name)
	if err != nil || stateFromCookie == "" {
		resp.BadRequest(json.LogErr(err), json.LogMessage("missing or invalid OIDC state cookie"))
		return
	}
	if stateFromCookie != state {
		resp.BadRequest(json.LogErr(errors.New("OIDC state mismatch in callback")))
		return
	}
	stateCookie.Delete(w)

	token, err := h.OIDCClient.AuthorizationCodeToken(r.Context(), code, h.RedirectURI)
	if err != nil {
		resp.InternalServerError(json.LogErr(err), json.LogMessage("OIDC token exchange failed"))
		return
	}

	session := Session{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, Expiry: token.Expiry}
	if err := h.Cookies.Set(w, session); err != nil {
		resp.InternalServerError(json.LogErr(err), json.LogMessage("failed to set session cookies"))
		return
	}

	http.Redirect(w, r, h.PostLoginPath, http.StatusFound)
}

// logout ends the user's session at the identity provider, clears the session
// cookies and redirects to PostLogoutPath. It does nothing but redirect when
// the request carries no session cookie. A cross-site POST arrives without
// one, because the cookies are SameSite=Lax, and must not be answered with
// Set-Cookie headers that sign the user out.
func (h *AuthHandler) logout(w http.ResponseWriter, r *http.Request) {
	if h.Cookies.Present(r) {
		h.endProviderSession(r)
		h.Cookies.Clear(w)
	}
	http.Redirect(w, r, h.PostLogoutPath, http.StatusFound)
}

// endProviderSession ends the user's single sign-on session at the identity
// provider. Without it, the redirect after logout lands on the login route
// and the provider signs the user straight back in. A failure is logged, not
// returned: the session cookies are cleared either way.
func (h *AuthHandler) endProviderSession(r *http.Request) {
	if h.OIDCClient == nil {
		return
	}
	log := zerolog.Ctx(r.Context())

	session, err := h.Cookies.Get(r)
	if err != nil || session.RefreshToken == "" {
		log.Warn().Err(err).Msg("no refresh token in session; identity provider session not ended")
		return
	}
	if err := h.OIDCClient.EndSession(r.Context(), session.RefreshToken); err != nil {
		log.Warn().Err(err).Msg("failed to end identity provider session")
	}
}

func (h *AuthHandler) config(w http.ResponseWriter, r *http.Request) {
	json.NewResponseFromRequest(w, r).OK(json.Data(h.PublicConfig))
}

// plainCookieValue reads an unencrypted cookie written by
// oidcmw.CookieConfig, which query-escapes its value.
func plainCookieValue(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return url.QueryUnescape(cookie.Value)
}

package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/dioad/auth/oidc"
)

var (
	DefaultCookieDomain        = "localhost"
	DefaultCookiePath          = "/"
	DefaultTokenCookieName     = "oidc_token"
	DefaultTokenCookieMaxAge   = time.Hour
	DefaultStateCookieName     = "oidc_state"
	DefaultStateCookieMaxAge   = 5 * time.Minute
	DefaultRefreshCookieName   = "oidc_refresh"
	DefaultRefreshCookieMaxAge = 24 * time.Hour
	// #nosec G101
	DefaultTokenExpiryCookieName = "oidc_expires_in"
)

type CookieConfig struct {
	Name   string        `json:"name" mapstructure:"name"`
	Domain string        `json:"domain,omitzero" mapstructure:"domain,omitzero"`
	Secure bool          `json:"secure,omitzero" mapstructure:"secure,omitzero"`
	Path   string        `json:"path,omitzero" mapstructure:"path,omitzero"`
	MaxAge time.Duration `json:"max_age,omitzero" mapstructure:"max-age,omitzero"`
}

func (c CookieConfig) Cookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     c.Name,
		Domain:   c.Domain,
		HttpOnly: true,
		Secure:   c.Secure,
		Path:     c.Path,
		SameSite: http.SameSiteLaxMode,
		Value:    url.QueryEscape(value),
		MaxAge:   int(c.MaxAge.Seconds()),
	}
}

func (c CookieConfig) Set(w http.ResponseWriter, value string) {
	http.SetCookie(w, c.Cookie(value))
}

func (c CookieConfig) Delete(w http.ResponseWriter) {
	cookie := c.Cookie("")
	cookie.MaxAge = 0
	http.SetCookie(w, cookie)
}

type OIDCConfig struct {
	Scopes      []string `json:"scopes,omitzero" mapstructure:"scopes,omitzero"`
	RedirectURI string   `json:"redirect_uri,omitzero" mapstructure:"redirect-uri,omitzero"`

	TokenCookie       CookieConfig `json:"token_cookie,omitzero" mapstructure:"token-cookie,omitzero"`
	StateCookie       CookieConfig `json:"state_cookie,omitzero" mapstructure:"state-cookie,omitzero"`
	RefreshCookie     CookieConfig `json:"refresh_cookie,omitzero" mapstructure:"refresh-cookie,omitzero"`
	TokenExpiryCookie CookieConfig `json:"token_expiry,omitzero" mapstructure:"token-expiry,omitzero"`
	RedirectCookie    CookieConfig `json:"redirect_cookie,omitzero" mapstructure:"redirect-cookie,omitzero"`

	RefreshWindow time.Duration    `json:"refresh_window,omitzero" mapstructure:"refresh-window,omitzero"`
	Now           func() time.Time `json:"-" mapstructure:"-"`
	LoginPath     string           `json:"login_path,omitzero" mapstructure:"login-path,omitzero"`
	LogoutPath    string           `json:"logout_path,omitzero" mapstructure:"logout-path,omitzero"`
}

type Handler struct {
	Client *oidc.Client
	Config OIDCConfig

	// callbackPath is the URL path component of Config.RedirectURI, precomputed
	// once so Wrap doesn't need to reparse it on every request.
	callbackPath string

	// bearerPassthrough configures whether Wrap forwards requests carrying a
	// non-empty Authorization header straight to next without validating the
	// OIDC session cookie. See WithBearerPassthrough.
	bearerPassthrough bool
}

// WithBearerPassthrough configures whether Wrap forwards a request carrying a
// non-empty Authorization header to next without checking the OIDC session
// cookie, on the assumption a separately chained bearer-token validator
// (e.g. jwt.Handler) will authenticate that header itself. Defaults to false.
//
// Only enable this when this Handler is explicitly chained ahead of another
// auth middleware that validates the Authorization header — never when it is
// used as a sole auth gate (e.g. via resolveOIDCHandler/WithServerAuth),
// since an unvalidated header would then let any request bypass
// authentication entirely.
func (h *Handler) WithBearerPassthrough(v bool) *Handler {
	h.bearerPassthrough = v
	return h
}

// applyCookieDefaults fills in Name, Path, and MaxAge when unset, using the
// package-level Default* values. Domain is deliberately left untouched: an
// empty Domain is the correct, safe default (the browser scopes the cookie to
// the current host), whereas defaulting it to DefaultCookieDomain
// ("localhost") would break every real deployment using a custom domain.
func applyCookieDefaults(c CookieConfig, name string, maxAge time.Duration) CookieConfig {
	if c.Name == "" {
		c.Name = name
	}
	if c.Path == "" {
		c.Path = DefaultCookiePath
	}
	if c.MaxAge == 0 {
		c.MaxAge = maxAge
	}
	return c
}

func NewHandler(client *oidc.Client, cfg OIDCConfig) *Handler {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.LoginPath == "" {
		cfg.LoginPath = "/login"
	}
	if cfg.LogoutPath == "" {
		cfg.LogoutPath = "/logout"
	}

	cfg.TokenCookie = applyCookieDefaults(cfg.TokenCookie, DefaultTokenCookieName, DefaultTokenCookieMaxAge)
	cfg.StateCookie = applyCookieDefaults(cfg.StateCookie, DefaultStateCookieName, DefaultStateCookieMaxAge)
	cfg.RefreshCookie = applyCookieDefaults(cfg.RefreshCookie, DefaultRefreshCookieName, DefaultRefreshCookieMaxAge)
	cfg.TokenExpiryCookie = applyCookieDefaults(cfg.TokenExpiryCookie, DefaultTokenExpiryCookieName, DefaultTokenCookieMaxAge)

	var callbackPath string
	if u, err := url.Parse(cfg.RedirectURI); err == nil {
		callbackPath = u.Path
	}

	return &Handler{
		Client:       client,
		Config:       cfg,
		callbackPath: callbackPath,
	}
}

// LoginPath returns the path AuthStart should be registered at.
func (h *Handler) LoginPath() string {
	return h.Config.LoginPath
}

// CallbackPath returns the URL path component of Config.RedirectURI that
// Callback should be registered at, or "" if RedirectURI is unset or
// unparseable.
func (h *Handler) CallbackPath() string {
	return h.callbackPath
}

// LogoutPath returns the path Logout should be registered at.
func (h *Handler) LogoutPath() string {
	return h.Config.LogoutPath
}

// isPublicPath reports whether path is one of this handler's own
// login/callback/logout routes, which must never be gated by Wrap — otherwise
// an unauthenticated request to them would be redirected right back to
// LoginPath, looping forever and preventing login from ever completing.
func (h *Handler) isPublicPath(path string) bool {
	if path == h.Config.LoginPath {
		return true
	}
	if h.callbackPath != "" && path == h.callbackPath {
		return true
	}
	if h.Config.LogoutPath != "" && path == h.Config.LogoutPath {
		return true
	}
	return false
}

func (h *Handler) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		if h.bearerPassthrough && r.Header.Get("Authorization") != "" {
			next.ServeHTTP(w, r)
			return
		}

		token, err := h.extractTokenFromCookies(r)
		if err != nil {
			h.redirectToLogin(w, r)
			return
		}

		token, err = h.refreshIfNeeded(w, r, token)
		if err != nil {
			h.redirectToLogin(w, r)
			return
		}

		// Enrich the request-scoped logger so auth_source propagates to child
		// handlers and the deferred access log entry.
		zerolog.Ctx(r.Context()).UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("auth_source", "oidc_session")
		})
		ctx := ContextWithAccessToken(r.Context(), token.AccessToken)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// redirectToLogin clears any stale session cookies and sends the browser to
// the configured login path.
func (h *Handler) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	h.clearAllCookies(w)
	http.Redirect(w, r, h.Config.LoginPath, http.StatusSeeOther)
}

// refreshIfNeeded refreshes token via the OIDC provider when it falls inside
// the configured refresh window, persisting the refreshed token to cookies.
// It returns token unchanged when no refresh is needed.
func (h *Handler) refreshIfNeeded(w http.ResponseWriter, r *http.Request, token *oauth2.Token) (*oauth2.Token, error) {
	if !shouldRefreshTokenBasedOnExpiry(token.Expiry, h.Config.RefreshWindow, h.Config.Now()) {
		return token, nil
	}

	refreshedToken, err := h.Client.RefreshToken(r.Context(), token.RefreshToken)
	if err != nil {
		zerolog.Ctx(r.Context()).Error().Err(err).Msg("Failed to refresh token")
		return nil, err
	}

	h.saveTokenToCookies(w, refreshedToken)
	zerolog.Ctx(r.Context()).UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Bool("token_refreshed", true)
	})
	return refreshedToken, nil
}

// AuthStart initiates the OIDC authentication flow.
func (h *Handler) AuthStart() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := generateState()
		if err != nil {
			zerolog.Ctx(r.Context()).Error().Err(err).Msg("Failed to generate auth state")
			http.Error(w, "Failed to start authentication", http.StatusInternalServerError)
			return
		}
		authURL, err := h.Client.AuthorizationCodeRedirectFlow(r.Context(), state, h.Config.Scopes, h.Config.RedirectURI)
		if err != nil {
			zerolog.Ctx(r.Context()).Error().Err(err).Msg("Failed to create authorization URL")
			http.Error(w, "Failed to create authorization URL", http.StatusInternalServerError)
			return
		}
		h.Config.StateCookie.Set(w, state)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// Logout clears all authentication cookies and redirects to root.
func (h *Handler) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.clearAllCookies(w)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// Callback handles the OIDC provider callback and sets cookies.
func (h *Handler) Callback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := zerolog.Ctx(r.Context())
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" {
			log.Error().Msg("Missing code in callback")
			http.Error(w, "Missing code", http.StatusBadRequest)
			return
		}
		if state == "" {
			log.Error().Msg("Missing state in callback")
			http.Error(w, "Missing state", http.StatusBadRequest)
			return
		}
		stateFromCookie, err := extractValueFromCookie(r, h.Config.StateCookie.Name)
		if stateFromCookie == "" || err != nil {
			log.Error().Err(err).Msg("Missing or invalid state cookie")
			http.Error(w, "Invalid state cookie", http.StatusBadRequest)
			return
		}
		if stateFromCookie != state {
			log.Error().Msg("Invalid state in callback")
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}
		h.Config.StateCookie.Delete(w)
		token, err := h.Client.AuthorizationCodeToken(r.Context(), code, h.Config.RedirectURI)
		if err != nil {
			log.Error().Err(err).Msg("Token exchange failed")
			http.Error(w, "Token exchange failed", http.StatusInternalServerError)
			return
		}
		h.saveTokenToCookies(w, token)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (h *Handler) extractTokenFromCookies(r *http.Request) (*oauth2.Token, error) {
	accessToken, err := extractValueFromCookie(r, h.Config.TokenCookie.Name)
	if err != nil {
		return nil, err
	}
	refreshToken, err := extractValueFromCookie(r, h.Config.RefreshCookie.Name)
	if err != nil {
		return nil, err
	}
	expiryValue, err := extractValueFromCookie(r, h.Config.TokenExpiryCookie.Name)
	if err != nil {
		return nil, err
	}
	expiry, err := time.Parse(time.RFC3339, expiryValue)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       expiry,
	}, nil
}

func (h *Handler) saveTokenToCookies(w http.ResponseWriter, token *oauth2.Token) {
	h.Config.TokenCookie.Set(w, token.AccessToken)
	h.Config.RefreshCookie.Set(w, token.RefreshToken)
	h.Config.TokenExpiryCookie.Set(w, token.Expiry.Format(time.RFC3339))
}

func (h *Handler) clearAllCookies(w http.ResponseWriter) {
	h.Config.TokenCookie.Delete(w)
	h.Config.RefreshCookie.Delete(w)
	h.Config.TokenExpiryCookie.Delete(w)
}

func extractValueFromCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return url.QueryUnescape(cookie.Value)
}

func shouldRefreshTokenBasedOnExpiry(expiry time.Time, window time.Duration, now time.Time) bool {
	return expiry.Sub(now) <= window
}

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

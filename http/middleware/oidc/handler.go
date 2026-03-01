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
	DefaultCookieDomain          = "localhost"
	DefaultCookiePath            = "/"
	DefaultTokenCookieName       = "oidc_token"
	DefaultTokenCookieMaxAge     = time.Hour
	DefaultStateCookieName       = "oidc_state"
	DefaultStateCookieMaxAge     = 5 * time.Minute
	DefaultRefreshCookieName     = "oidc_refresh"
	DefaultRefreshCookieMaxAge   = 24 * time.Hour
	DefaultTokenExpiryCookieName = "oidc_expires_in"
)

type CookieConfig struct {
	Name   string
	Domain string
	Secure bool
	Path   string
	MaxAge time.Duration
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
	Scopes      []string
	RedirectURI string

	TokenCookieConfig       CookieConfig
	StateCookieConfig       CookieConfig
	RefreshCookieConfig     CookieConfig
	TokenExpiryCookieConfig CookieConfig
	RedirectCookieConfig    CookieConfig

	RefreshWindow time.Duration
	Now           func() time.Time `json:"-,omitzero"`
	LoginPath     string
}

type Handler struct {
	Client *oidc.Client
	Config OIDCConfig
	logger zerolog.Logger
}

func NewHandler(client *oidc.Client, cfg OIDCConfig, logger zerolog.Logger) *Handler {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Handler{
		Client: client,
		Config: cfg,
		logger: logger,
	}
}

func (h *Handler) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			next.ServeHTTP(w, r)
			return
		}

		token, err := h.extractTokenFromCookies(r)
		if err != nil {
			h.clearAllCookies(w)
			http.Redirect(w, r, h.Config.LoginPath, http.StatusSeeOther)
			return
		}

		if shouldRefreshTokenBasedOnExpiry(token.Expiry, h.Config.RefreshWindow, h.Config.Now()) {
			refreshedToken, err := h.Client.RefreshToken(r.Context(), token.RefreshToken)
			if err != nil {
				h.logger.Error().Err(err).Msg("Failed to refresh token")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			h.saveTokenToCookies(w, refreshedToken)
			token = refreshedToken
		}
		ctx := ContextWithAccessToken(r.Context(), token.AccessToken)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthStart initiates the OIDC authentication flow.
func (h *Handler) AuthStart() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := generateState()
		authURL, err := h.Client.AuthorizationCodeRedirectFlow(r.Context(), state, h.Config.Scopes, h.Config.RedirectURI)
		if err != nil {
			h.logger.Error().Err(err).Msg("Failed to create authorization URL")
			http.Error(w, "Failed to create authorization URL", http.StatusInternalServerError)
			return
		}
		h.Config.StateCookieConfig.Set(w, state)
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
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		stateFromCookie, err := extractValueFromCookie(r, h.Config.StateCookieConfig.Name)
		if stateFromCookie == "" || err != nil {
			h.logger.Error().Err(err).Msg("Missing or invalid state cookie")
			http.Error(w, "Invalid state cookie", http.StatusBadRequest)
			return
		}
		if stateFromCookie != state {
			h.logger.Error().Msg("Invalid state in callback")
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}
		h.Config.StateCookieConfig.Delete(w)
		token, err := h.Client.AuthorizationCodeToken(r.Context(), code, h.Config.RedirectURI)
		if err != nil {
			h.logger.Error().Err(err).Msg("Token exchange failed")
			http.Error(w, "Token exchange failed", http.StatusInternalServerError)
			return
		}
		h.saveTokenToCookies(w, token)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (h *Handler) extractTokenFromCookies(r *http.Request) (*oauth2.Token, error) {
	accessToken, err := extractValueFromCookie(r, h.Config.TokenCookieConfig.Name)
	if err != nil {
		return nil, err
	}
	refreshToken, err := extractValueFromCookie(r, h.Config.RefreshCookieConfig.Name)
	if err != nil {
		return nil, err
	}
	expiryValue, err := extractValueFromCookie(r, h.Config.TokenExpiryCookieConfig.Name)
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
	h.Config.TokenCookieConfig.Set(w, token.AccessToken)
	h.Config.RefreshCookieConfig.Set(w, token.RefreshToken)
	h.Config.TokenExpiryCookieConfig.Set(w, token.Expiry.Format(time.RFC3339))
}

func (h *Handler) clearAllCookies(w http.ResponseWriter) {
	h.Config.TokenCookieConfig.Delete(w)
	h.Config.RefreshCookieConfig.Delete(w)
	h.Config.TokenExpiryCookieConfig.Delete(w)
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

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

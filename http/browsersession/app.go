package browsersession

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"

	"golang.org/x/oauth2"

	oidcmw "github.com/dioad/auth/http/middleware/oidc"
	"github.com/dioad/auth/oidc"
)

// Config configures a browser session app.
type Config struct {
	// OIDC is the identity provider, the client registered with it and the
	// cookie attributes. OIDC.LoginPath is the absolute path the browser is
	// sent to when it has no session; App.Auth must be mounted so that its
	// /login route is served there. OIDC.RedirectURI must reach App.Auth's
	// /callback route.
	OIDC oidcmw.BrowserConfig `mapstructure:"oidc"`

	// CookieEncryptionKey encrypts the session cookies. It is 64 hexadecimal
	// characters (an AES-256 key), for example from "openssl rand -hex 32".
	// Changing it ends every session.
	CookieEncryptionKey string `mapstructure:"cookie-encryption-key"`

	// PostLoginPath is where the browser is sent after login. Defaults to "/".
	PostLoginPath string `mapstructure:"post-login-path"`
	// PostLogoutPath is where the browser is sent after logout. Defaults to "/".
	PostLogoutPath string `mapstructure:"post-logout-path"`
}

// App is the set of handlers that make up a browser session app. Mount each
// under its own path prefix, with the prefix stripped.
type App struct {
	// Auth serves /login, /callback, /logout and /config. See AuthHandler.
	Auth http.Handler
	// UI serves the single-page app to browsers with a session and redirects
	// the rest to login.
	UI http.Handler
	// API is the caller's API handler behind the session: the session cookie
	// is promoted to an Authorization header and refreshed when due.
	API http.Handler
}

// NewApp wires a browser session around apiHandler and the single-page app in
// staticFS.
//
// apiHandler receives each request with the session's access token in the
// Authorization header. It must validate that token itself, typically with
// server.OAuth2ValidatorHandler followed by principal extraction: NewApp
// checks that a session exists, not what the session is allowed to do.
func NewApp(cfg Config, apiHandler http.Handler, staticFS fs.FS) (*App, error) {
	if apiHandler == nil {
		return nil, errors.New("api handler is required")
	}
	if staticFS == nil {
		return nil, errors.New("static file system is required")
	}
	if err := cfg.OIDC.Validate(); err != nil {
		return nil, fmt.Errorf("invalid oidc config: %w", err)
	}

	oidcCfg := cfg.OIDC.ToOIDCConfig()
	oidcCfg.TokenCookie.Name = DefaultTokenCookieName
	oidcCfg.RefreshCookie.Name = DefaultRefreshCookieName
	oidcCfg.TokenExpiryCookie.Name = DefaultExpiryCookieName

	cookies, err := NewCookieSet(cfg.CookieEncryptionKey, oidcCfg.TokenCookie, oidcCfg.RefreshCookie, oidcCfg.TokenExpiryCookie)
	if err != nil {
		return nil, err
	}

	client, err := oidc.NewClientFromConfig(new(cfg.OIDC.ToClientConfig()))
	if err != nil {
		return nil, fmt.Errorf("failed to create oidc client: %w", err)
	}
	refresh := func(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
		return client.RefreshToken(ctx, refreshToken)
	}

	auth := &AuthHandler{
		OIDCHandler:    oidcmw.NewHandler(client, oidcCfg),
		OIDCClient:     client,
		RedirectURI:    oidcCfg.RedirectURI,
		PostLoginPath:  pathOrRoot(cfg.PostLoginPath),
		PostLogoutPath: pathOrRoot(cfg.PostLogoutPath),
		Cookies:        cookies,
		PublicConfig: PublicConfig{
			Issuer:   strings.TrimSpace(cfg.OIDC.Issuer),
			ClientID: strings.TrimSpace(cfg.OIDC.ClientID),
		},
	}

	api := RefreshMiddleware(cookies, oidcCfg.RefreshWindow, refresh)(apiHandler)
	api = CookieAuthMiddleware(cookies)(api)

	ui := SessionGuard(cookies, oidcCfg.LoginPath, oidcCfg.RefreshWindow, refresh)(SPAHandler(staticFS))

	return &App{Auth: auth.Handler(), UI: ui, API: api}, nil
}

func pathOrRoot(path string) string {
	if path = strings.TrimSpace(path); path != "" {
		return path
	}
	return "/"
}

package oidc

import (
	"fmt"
	"strings"
	"time"

	"github.com/dioad/util"

	authoidc "github.com/dioad/auth/oidc"
)

var defaultBrowserScopes = []string{"openid", "profile", "email"}

// BrowserConfig is a shared configuration contract for interactive, browser-based
// OIDC login flows.
//
// Use BrowserConfig when your server application needs to:
//   - redirect a human user to an OIDC provider login page,
//   - exchange an authorization code for tokens server-side, and
//   - keep the browser session in HTTP-only cookies.
//
// Typical usage:
//   - call Validate to fail fast on insecure or incomplete configuration,
//   - call ToClientConfig to construct an oidc.Client, then
//   - call ToOIDCConfig to configure this package's middleware Handler.
//
// BrowserConfig is intentionally focused on browser sessions. For machine-to-machine
// APIs or bearer-token-only validation, prefer JWT validator configuration instead
// of browser login middleware.
type BrowserConfig struct {
	// Issuer is the OIDC issuer/discovery base URL.
	Issuer string `json:"issuer" mapstructure:"issuer"`
	// ClientID is the OAuth2/OIDC client identifier registered with the provider.
	ClientID string `json:"client_id" mapstructure:"client-id"`
	// ClientSecret is the confidential client secret used in code exchange.
	ClientSecret string `json:"client_secret" mapstructure:"client-secret"`
	// Scopes controls requested OAuth2 scopes; defaults to openid/profile/email when omitted.
	Scopes []string `json:"scopes,omitzero" mapstructure:"scopes,omitzero"`
	// RedirectURI is the absolute callback URL registered with the OIDC provider.
	RedirectURI string `json:"redirect_uri" mapstructure:"redirect-uri"`

	// LoginPath is the local route that initiates login; defaults to /auth/login.
	LoginPath string `json:"login_path,omitzero" mapstructure:"login-path,omitzero"`

	// CookieDomain sets the optional cookie domain attribute for session cookies.
	CookieDomain string `json:"cookie_domain,omitzero" mapstructure:"cookie-domain,omitzero"`
	// CookieSecure controls the cookie Secure attribute and must be true for authenticated flows.
	CookieSecure bool `json:"cookie_secure,omitzero" mapstructure:"cookie-secure,omitzero"`
}

// Validate checks that BrowserConfig is suitable for authenticated browser OIDC
// flows and enforces secure-cookie sessions.
func (c BrowserConfig) Validate() error {
	if strings.TrimSpace(c.Issuer) == "" {
		return fmt.Errorf("issuer is required")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("client-id is required")
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		return fmt.Errorf("client-secret is required")
	}
	if strings.TrimSpace(c.RedirectURI) == "" {
		return fmt.Errorf("redirect-uri is required")
	}
	if !c.CookieSecure {
		return fmt.Errorf("cookie-secure must be true for authenticated browser OIDC")
	}
	return nil
}

// ToClientConfig converts BrowserConfig into oidc.ClientConfig used to build an
// OIDC client for authorization-code token exchange.
func (c BrowserConfig) ToClientConfig() authoidc.ClientConfig {
	return authoidc.ClientConfig{
		EndpointConfig: authoidc.EndpointConfig{URL: strings.TrimSpace(c.Issuer)},
		ClientID:       strings.TrimSpace(c.ClientID),
		ClientSecret:   *util.NewMaskedString(strings.TrimSpace(c.ClientSecret)),
	}
}

// ToOIDCConfig converts BrowserConfig into middleware OIDCConfig suitable for
// Handler.
//
// Call Validate before using the converted configuration in production paths.
func (c BrowserConfig) ToOIDCConfig() OIDCConfig {
	loginPath := strings.TrimSpace(c.LoginPath)
	if loginPath == "" {
		loginPath = "/auth/login"
	}

	scopes := c.Scopes
	if len(scopes) == 0 {
		scopes = defaultBrowserScopes
	}

	trimmedDomain := strings.TrimSpace(c.CookieDomain)

	return OIDCConfig{
		Scopes:      scopes,
		RedirectURI: strings.TrimSpace(c.RedirectURI),
		LoginPath:   loginPath,
		TokenCookie: CookieConfig{
			Name:   "auth_token",
			Domain: trimmedDomain,
			Secure: c.CookieSecure,
			Path:   "/",
			MaxAge: time.Hour,
		},
		StateCookie: CookieConfig{
			Name:   DefaultStateCookieName,
			Domain: trimmedDomain,
			Secure: c.CookieSecure,
			Path:   "/",
			MaxAge: DefaultStateCookieMaxAge,
		},
		RefreshCookie: CookieConfig{
			Name:   DefaultRefreshCookieName,
			Domain: trimmedDomain,
			Secure: c.CookieSecure,
			Path:   "/",
			MaxAge: DefaultRefreshCookieMaxAge,
		},
		TokenExpiryCookie: CookieConfig{
			Name:   DefaultTokenExpiryCookieName,
			Domain: trimmedDomain,
			Secure: c.CookieSecure,
			Path:   "/",
		},
		RefreshWindow: 5 * time.Minute,
	}
}

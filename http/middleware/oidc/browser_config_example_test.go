package oidc_test

import (
	"fmt"

	oidcmw "github.com/dioad/auth/http/middleware/oidc"
)

func ExampleBrowserConfig_authenticatedConsoleDefaults() {
	cfg := oidcmw.BrowserConfig{
		Issuer:       "https://auth.example.com/realms/connect",
		ClientID:     "connect-control-console",
		ClientSecret: "super-secret",
		RedirectURI:  "https://control.example.com/auth/callback",
		CookieSecure: true,
	}

	if err := cfg.Validate(); err != nil {
		fmt.Println("invalid config")
		return
	}

	clientCfg := cfg.ToClientConfig()
	mwCfg := cfg.ToOIDCConfig()

	fmt.Println(clientCfg.EndpointConfig.URL)
	fmt.Println(mwCfg.LoginPath)
	fmt.Println(mwCfg.Scopes)
	fmt.Println(mwCfg.TokenCookie.Secure)

	// Output:
	// https://auth.example.com/realms/connect
	// /auth/login
	// [openid profile email]
	// true
}

func ExampleBrowserConfig_customLoginPathAndScopes() {
	cfg := oidcmw.BrowserConfig{
		Issuer:       "https://issuer.example",
		ClientID:     "admin-ui",
		ClientSecret: "secret",
		RedirectURI:  "https://admin.example/auth/callback",
		CookieSecure: true,
		LoginPath:    "/console/login",
		Scopes:       []string{"openid", "profile", "groups"},
	}

	mwCfg := cfg.ToOIDCConfig()
	fmt.Println(mwCfg.LoginPath)
	fmt.Println(mwCfg.Scopes)

	// Output:
	// /console/login
	// [openid profile groups]
}

func ExampleBrowserConfig_Validate_insecureCookieRejected() {
	cfg := oidcmw.BrowserConfig{
		Issuer:       "https://issuer.example",
		ClientID:     "admin-ui",
		ClientSecret: "secret",
		RedirectURI:  "https://admin.example/auth/callback",
		CookieSecure: false,
	}

	fmt.Println(cfg.Validate())

	// Output:
	// cookie-secure must be true for authenticated browser OIDC
}
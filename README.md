# dioad/auth

Authentication and authorization helpers for Go services, including OIDC client utilities, JWT validation helpers, HTTP middleware, and TLS configuration helpers.

## Packages

- `oidc`: OpenID Connect client, token sources, and validation helpers (Keycloak, GitHub Actions, AWS, Fly.io).
- `jwt`: Token validation helpers and claim predicates, plus composable multi-validator support.
- `http`: HTTP authentication middleware for Basic, GitHub App, and HMAC signatures, plus JWT/OIDC wiring helpers.
- `tls`: TLS configuration helpers for clients and servers (cert loading, client auth).

## OIDC quick start (token validation)

```go
endpoint, _ := oidc.NewEndpoint("https://issuer.example")
client := oidc.NewClient(
    endpoint,
    oidc.WithKeyFunc(func(ctx context.Context) (interface{}, error) {
        return &publicKey, nil
    }),
)

claims, err := client.ValidateToken(ctx, tokenString, []string{"audience"})
```

## HTTP middleware quick start

```go
handler, _ := authhttp.NewHandler(&authhttp.ServerConfig{
    HMACAuthConfig: hmac.Config{Secret: "shared-secret"},
})

http.Handle("/secure", handler.Wrap(myHandler))
```

## Browser OIDC shared configuration

For interactive browser login flows, use `http/middleware/oidc.BrowserConfig` as a reusable config contract.

```go
browser := oidcmw.BrowserConfig{
    Issuer:       "https://issuer.example",
    ClientID:     "console-ui",
    ClientSecret: "redacted",
    RedirectURI:  "https://console.example/auth/callback",
    CookieSecure: true,
}
if err := browser.Validate(); err != nil {
    panic(err)
}

oidcClient, err := oidc.NewClientFromConfig(new(browser.ToClientConfig()))
if err != nil {
    panic(err)
}

mw := oidcmw.NewHandler(oidcClient, browser.ToOIDCConfig(), zerolog.Nop())
http.Handle("/ui/", mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
})))
```

`BrowserConfig.Validate` enforces secure cookie use for authenticated browser sessions.

## OIDC configuration ownership (one way to do it)

- Use `oidc.ClientConfig` for OIDC client/token exchange configuration.
- Use `http/middleware/oidc.BrowserConfig` for browser login/session flows.
- `http/oidc.Config` remains for backward compatibility and is deprecated in favor of `oidc.Config`.

This keeps provider/client concerns in `oidc` and browser-session concerns in middleware,
with adapter methods (`ToClientConfig`, `ToOIDCConfig`) making the secure path the easy path.

## Testability seams

The OIDC package provides explicit seams for fast, deterministic tests:

- `WithHTTPClient` to inject a custom `HTTPDoer` for outbound requests.
- `WithClock` to control time-dependent behavior.
- `WithKeyFunc`/`WithJWKSProvider` to control verification keys without live JWKS endpoints.
- `NewTokenSourceFromConfigWithFactories` to inject token source factories and a `TokenStore` implementation.

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

## Testability seams

The OIDC package provides explicit seams for fast, deterministic tests:

- `WithHTTPClient` to inject a custom `HTTPDoer` for outbound requests.
- `WithClock` to control time-dependent behavior.
- `WithKeyFunc`/`WithJWKSProvider` to control verification keys without live JWKS endpoints.
- `NewTokenSourceFromConfigWithFactories` to inject token source factories and a `TokenStore` implementation.

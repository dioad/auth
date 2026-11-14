# OIDC token validation

An HTTP server that accepts GitHub Actions OIDC tokens. The validator is
global middleware: every request needs a valid bearer token in the
`Authorization` header. Cookies are not read.

For an API with principal extraction and a role check, see
[api-auth](../api-auth). For a browser app with a login, see
[browser-session](../browser-session).

## Running the example

```bash
go run ./examples/oidc-auth
```

| Variable | Meaning | Default |
|---|---|---|
| `LISTEN_ADDR` | address to listen on | `127.0.0.1:8080` |
| `OIDC_AUDIENCE` | accepted token audience | `https://github.com/my-org` |

Then call it with a token that GitHub Actions issued for that audience. A
request with no token is refused with 401:

```bash
curl -i http://127.0.0.1:8080/secure
curl -H 'Authorization: Bearer <token>' http://127.0.0.1:8080/secure
```

See [githubactions-oidc](../githubactions-oidc) for getting a token inside a
workflow.

## What it demonstrates

- Creating an OIDC validator configuration for GitHub Actions
- Using the OAuth2 validator as global middleware
- Shutting down on SIGTERM

See [main.go](main.go) for the code.

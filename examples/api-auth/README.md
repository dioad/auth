# API authentication

An API protected by JWT validation, principal extraction and a role check.

| Route | Needs |
|---|---|
| `GET /whoami` | any valid token; returns the principal and its roles |
| `GET /admin` | the `api-admins` role, granted by the `groups` claim |

The code is in [main.go](main.go). The same chain appears as runnable
examples next to the packages: `ExampleOAuth2ValidatorHandler` in
`http/server`, `ExamplePrincipalExtractionHandler` in `http/middleware`, and
`ExampleCheck_roleAuthorizer` in `authz`.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `LISTEN_ADDR` | address to listen on | `127.0.0.1:8080` |
| `AUDIENCE` | accepted token audience | `api-auth` |
| `ISSUER` | OIDC issuer to validate tokens from | |
| `HMAC_SECRET` | validate tokens with this shared secret instead of an issuer | |

Set `ISSUER` for a real deployment. `HMAC_SECRET` is for local development and
CI only: a shared secret lets anyone who knows it mint a token.

Tokens are read from the `Authorization` header only. A valid token sent in a
cookie is refused.

## Try it

Start the server in shared-secret mode:

```bash
HMAC_SECRET=local-secret go run ./examples/api-auth
```

In another terminal, mint a token with the matching secret and audience. The
`api-admins` group is the one that `/admin` accepts:

```bash
export SMOKE_JWT_SECRET=local-secret SMOKE_JWT_AUDIENCE=api-auth
ADMIN=$(./scripts/gen_smoke_token.py --group api-admins)
USER=$(./scripts/gen_smoke_token.py)
```

A token that passes:

```bash
curl -i -H "Authorization: Bearer $ADMIN" http://127.0.0.1:8080/admin
# HTTP/1.1 200 OK
# welcome, admin
```

A token that is refused, because the principal has no role for `/admin`:

```bash
curl -i -H "Authorization: Bearer $USER" http://127.0.0.1:8080/admin
# HTTP/1.1 403 Forbidden
```

No token, or one that does not validate, is refused earlier:

```bash
curl -i http://127.0.0.1:8080/whoami
# HTTP/1.1 401 Unauthorized
```

Stop the server with Ctrl-C or SIGTERM. It finishes in-flight requests and
exits 0.

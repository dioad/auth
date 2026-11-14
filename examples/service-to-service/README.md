# Service-to-service calls

Calls another service as this service's own identity, using
`oidc.NewIdentityClient`. The program makes one request to `TARGET_URL`, prints
the response and exits. It exits non-zero if the target answers 4xx or 5xx.

`oidc.NewIdentityClient` is shown with an OAuth2 token endpoint in
`ExampleNewIdentityClient`. The code here is in [main.go](main.go).

## Identities

| Set | Identity |
|---|---|
| `IDENTITY_TYPE` (`githubactions`, `flyio` or `aws`) and `IDENTITY_AUDIENCE` | the workload identity of the platform the program runs on |
| `IDENTITY_TOKEN_FILE` | a token read from a file |
| `IDENTITY_ISSUER`, `IDENTITY_CLIENT_ID` and `IDENTITY_CLIENT_SECRET` | an OAuth2 client, by the client credentials grant |
| none of these | no identity: the call carries no token |

`IDENTITY_AUDIENCE` must be an audience the target accepts. A workload
identity only exists on its platform: `githubactions` needs a workflow with
`id-token: write`.

## Try it against api-auth

Start [api-auth](../api-auth) in shared-secret mode, then write a token file
for a caller in the `api-admins` group:

```bash
HMAC_SECRET=local-secret go run ./examples/api-auth &

SMOKE_JWT_SECRET=local-secret SMOKE_JWT_AUDIENCE=api-auth \
  ./scripts/gen_smoke_token.py --group api-admins --write-token-file /tmp/caller-token.yaml >/dev/null
```

With the identity, the call passes:

```bash
TARGET_URL=http://127.0.0.1:8080/admin IDENTITY_TOKEN_FILE=/tmp/caller-token.yaml \
  go run ./examples/service-to-service
# welcome, admin
```

Without one, it is refused and the program exits 1:

```bash
TARGET_URL=http://127.0.0.1:8080/admin go run ./examples/service-to-service
# {"error":"unauthorized"}
```

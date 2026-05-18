# Auth Debug Utility

This utility detects the platform it's running on (AWS, GitHub Actions, or Fly.io), retrieves an OIDC token, and displays the decoded claims. It can also be used to output just the raw token for use in scripts.

## Usage

Run the utility using `go run`:

```bash
go run cmd/auth-debug/main.go
```

### Options

- `-audience`: Set the audience for the OIDC token.
- `-token-only`: Output only the raw token string (useful for scripts).
- `-platform`: Force a specific platform (`aws`, `github`, `flyio`) or use `auto` (default) to detect automatically.
- `-aws-signing-alg`: Set the AWS STS signing algorithm (e.g., `RS256`).
- `-verify`: After fetching the token, verify its signature against the platform's JWKS keys.

### Example: Get raw token with specific audience

```bash
TOKEN=$(go run cmd/auth-debug/main.go -token-only -audience "my-service")
curl -H "Authorization: Bearer $TOKEN" https://api.example.com
```

### Example: Fetch and verify a token

```bash
go run cmd/auth-debug/main.go -verify -platform github -audience "my-service"
```

## Validate subcommand

The `validate` subcommand reads a JWT from stdin, decodes its claims, and verifies
the token signature against the issuer's JWKS keys. This is useful for validating
tokens obtained from any source.

### Usage

```bash
echo "$TOKEN" | go run cmd/auth-debug/main.go validate
```

### Options

- `-issuer`: Override the issuer URL for JWKS discovery (by default extracted from the token's `iss` claim).
- `-audience`: Override the expected audience claim (by default extracted from the token's `aud` claim).

### Examples

Validate a token piped from another command:

```bash
go run cmd/auth-debug/main.go -token-only -platform github | go run cmd/auth-debug/main.go validate
```

Validate with an explicit issuer and audience:

```bash
echo "$TOKEN" | go run cmd/auth-debug/main.go validate -issuer "https://token.actions.githubusercontent.com" -audience "my-service"
```

## How it works

The utility attempts to fetch an OIDC token from the following sources in order:

1.  **AWS**: Uses the AWS STS `GetWebIdentityToken` API. Requires running in an AWS environment with an OIDC provider configured (e.g., EKS with IRSA).
2.  **GitHub Actions**: Uses the GitHub Actions OIDC provider. Requires running in a GitHub Actions workflow with `id-token: write` permissions.
3.  **Fly.io**: Uses the Fly.io OIDC agent via the Unix socket at `/.fly/api`. Requires running in a Fly.io machine.

If a token is successfully retrieved, it displays the platform name, token expiry, JWT header details (algorithm, key ID, type), and a pretty-printed JSON representation of the JWT claims.

When `--verify` is used or the `validate` subcommand is invoked, the tool extracts
the issuer (`iss`) from the token claims, fetches the provider's JWKS keys via
OpenID Connect discovery, displays the available JWKS keys (key ID, algorithm,
use, key type), and performs full signature verification.

## Debugging verification failures

The `verify_debug_test.go` file contains a suite of tests designed to be run
under GoLand's debugger. Each test creates a signed JWT against a local mock
identity provider and exercises a specific failure scenario:

- **Valid token** — end-to-end happy path.
- **Expired token** — token with `exp` in the past.
- **Wrong audience** — audience mismatch between token and validator.
- **Wrong issuer** — issuer mismatch between token claim and discovery URL.
- **Header & key details** — decodes both the JWT header and JWKS keys, logs
  details, and compares `kid`/`alg` for diagnosing key mismatch issues.
- **Full flow** — exercises the top-level `verifyToken` function.
- **Raw token** — decodes and verifies a real token you provide via
  environment variable (see below).

To debug a scenario, open `cmd/auth-debug/verify_debug_test.go` in GoLand,
click the gutter icon next to the test, and choose **Debug**. Set breakpoints
inside `verifyTokenWithConfig`, `fetchJWKSKeys`, `decodeHeader`, or
`decodeClaims` to step through the verification logic.

### Debugging with a raw access token

The `TestVerifyDebug_RawToken` test lets you feed a real JWT into the debug
pipeline. Set the `AUTH_DEBUG_TOKEN` environment variable to the raw token
string, then run or debug the test. The test decodes the header and claims,
fetches JWKS keys from the issuer, compares key IDs and algorithms, and
performs full signature verification — logging every detail along the way.

| Environment variable   | Required | Description                                           |
|------------------------|----------|-------------------------------------------------------|
| `AUTH_DEBUG_TOKEN`     | Yes      | The raw JWT to inspect and verify.                    |
| `AUTH_DEBUG_ISSUER`    | No       | Override the issuer URL for JWKS discovery.           |
| `AUTH_DEBUG_AUDIENCE`  | No       | Override the expected audience claim.                 |

The test is automatically skipped when `AUTH_DEBUG_TOKEN` is not set, so it
never fails during normal `go test` runs or in CI.

**From the command line:**

```bash
AUTH_DEBUG_TOKEN="eyJhbGci..." go test -run TestVerifyDebug_RawToken -v ./cmd/auth-debug/
```

**With issuer and audience overrides:**

```bash
AUTH_DEBUG_TOKEN="eyJhbGci..." \
  AUTH_DEBUG_ISSUER="https://accounts.google.com" \
  AUTH_DEBUG_AUDIENCE="my-service" \
  go test -run TestVerifyDebug_RawToken -v ./cmd/auth-debug/
```

**From GoLand:**

1. Open `cmd/auth-debug/verify_debug_test.go`.
2. Click the gutter icon next to `TestVerifyDebug_RawToken`.
3. Choose **Modify Run Configuration** and add `AUTH_DEBUG_TOKEN` (and
   optionally `AUTH_DEBUG_ISSUER` / `AUTH_DEBUG_AUDIENCE`) to the environment
   variables.
4. Click **Debug** and set breakpoints in `verifyTokenWithConfig`,
   `fetchJWKSKeys`, `decodeHeader`, or `decodeClaims`.

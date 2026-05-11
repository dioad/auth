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

### Example: Get raw token with specific audience

```bash
TOKEN=$(go run cmd/auth-debug/main.go -token-only -audience "my-service")
curl -H "Authorization: Bearer $TOKEN" https://api.example.com
```

## How it works

The utility attempts to fetch an OIDC token from the following sources in order:

1.  **AWS**: Uses the AWS STS `GetWebIdentityToken` API. Requires running in an AWS environment with an OIDC provider configured (e.g., EKS with IRSA).
2.  **GitHub Actions**: Uses the GitHub Actions OIDC provider. Requires running in a GitHub Actions workflow with `id-token: write` permissions.
3.  **Fly.io**: Uses the Fly.io OIDC agent via the Unix socket at `/.fly/api`. Requires running in a Fly.io machine.

If a token is successfully retrieved, it displays the platform name, token expiry, and a pretty-printed JSON representation of the JWT claims.

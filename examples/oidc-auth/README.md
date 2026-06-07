# OIDC/JWT Authentication

This example demonstrates how to configure an HTTP server with OpenID Connect (OIDC) and JWT authentication.

## Running the Example

```bash
go run github.com/dioad/net/examples/oidc-auth
```

Or build and run:
```bash
cd examples/oidc-auth
go build
./oidc-auth
```

Then test with a valid OIDC token:
```bash
curl -H 'Authorization: Bearer <your-token>' http://localhost:8080/secure
```

## What It Demonstrates

- Creating an OIDC validator configuration
- Setting up GitHub Actions OIDC authentication
- Using OAuth2 validator as global middleware
- Token validation for protected endpoints

## Code

See [main.go](main.go) for the complete executable example.

# GitHub Actions OIDC Example

This example demonstrates how to use GitHub Actions OIDC for authentication, including both obtaining and validating tokens.

## Running the Examples

### Client Example (Getting OIDC Token)

```bash
go run github.com/dioad/net/examples/githubactions-oidc/client
```

Or build and run:
```bash
cd examples/githubactions-oidc/client
go build
./client
```

### Validator Example (Validating OIDC Token)

```bash
go run github.com/dioad/net/examples/githubactions-oidc/validator
```

Or build and run:
```bash
cd examples/githubactions-oidc/validator
go build
./validator
```

**Note:** These examples require GitHub Actions environment variables. They will only work when run inside a GitHub Actions workflow with `id-token: write` permission.

## What It Demonstrates

- **Client** ([client/main.go](client/main.go)): Retrieving OIDC tokens from GitHub Actions, decoding and inspecting JWT claims
- **Validator** ([validator/main.go](validator/main.go)): Validating GitHub Actions OIDC tokens, creating OIDC validator configurations

## Configuration Examples

### Client Configuration (YAML)

For configuring a client to use GitHub Actions OIDC:

```yaml
identity:
  type: githubactions
  audience: "https://github.com/dioad"
```

### Server Configuration (YAML)

For configuring a server to validate GitHub Actions OIDC tokens:

```yaml
jwt-validators:
  - type: githubactions
    url: "https://token.actions.githubusercontent.com"
    audiences:
      - "https://github.com/dioad"
    issuer: "https://token.actions.githubusercontent.com"
```

## GitHub Actions Workflow Setup

To use OIDC in GitHub Actions, you need to grant the workflow `id-token: write` permission:

```yaml
name: Example Workflow

on:
  push:
    branches: [ main ]

permissions:
  id-token: write
  contents: read

jobs:
  example:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Use OIDC Token
        run: |
          go run main.go
        env:
          OIDC_AUDIENCE: "https://github.com/dioad"
```

## GitHub Actions Claims

The GitHub Actions OIDC token includes the following claims:

- `iss`: Token issuer (https://token.actions.githubusercontent.com)
- `sub`: Subject (e.g., repo:owner/repo:ref:refs/heads/main)
- `aud`: Audience (customizable)
- `actor`: GitHub username that triggered the workflow
- `repository`: Repository name (owner/repo)
- `repository_owner`: Repository owner
- `workflow`: Workflow name
- `ref`: Git ref that triggered the workflow
- `sha`: Commit SHA
- And many more...

For a complete list of claims, see the [GitHub documentation](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token).

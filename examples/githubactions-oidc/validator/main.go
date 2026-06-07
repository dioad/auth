package main

import (
	"context"
	"fmt"
	"os"

	"github.com/dioad/auth/oidc"
	"github.com/dioad/auth/oidc/githubactions"
)

func main() {
	ctx := context.Background()

	// Get the audience from environment or use default
	audience := os.Getenv("OIDC_AUDIENCE")
	if audience == "" {
		audience = "https://github.com/dioad"
	}

	fmt.Printf("Validating GitHub Actions OIDC token with audience: %s\n\n", audience)

	// Create a token source to get a token
	tokenSource := githubactions.NewTokenSource(githubactions.WithAudience(audience))
	token, err := tokenSource.Token()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get token: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nNote: This example must be run inside a GitHub Actions workflow\n")
		fmt.Fprintf(os.Stderr, "      with 'id-token: write' permission.\n")
		os.Exit(1)
	}

	fmt.Printf("✓ Retrieved OIDC token\n\n")

	// Create a validator config
	validatorConfig := oidc.ValidatorConfig{
		EndpointConfig: oidc.EndpointConfig{
			Type: "githubactions",
			URL:  "https://token.actions.githubusercontent.com",
		},
		Audiences: []string{audience},
		Issuer:    "https://token.actions.githubusercontent.com",
	}

	fmt.Printf("Creating validator:\n")
	fmt.Printf("  Issuer: %s\n", validatorConfig.Issuer)
	fmt.Printf("  Audiences: %v\n", validatorConfig.Audiences)
	fmt.Printf("  Endpoint: %s\n\n", validatorConfig.EndpointConfig.URL)

	// Create a validator
	validator, err := oidc.NewValidatorFromConfig(&validatorConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create validator: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Created validator\n\n")

	// Validate the token
	fmt.Printf("Validating token...\n")
	claims, err := validator.ValidateToken(ctx, token.AccessToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to validate token: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Token validated successfully\n")
	fmt.Printf("  Claims type: %T\n", claims)

	fmt.Printf("\n✓ GitHub Actions OIDC token validation completed\n")
}

//go:build ignore
// +build ignore

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

	fmt.Printf("Testing GitHub Actions OIDC token validation with audience: %s\n", audience)

	// Create a token source to get a token
	tokenSource := githubactions.NewTokenSource(githubactions.WithAudience(audience))
	token, err := tokenSource.Token()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get token: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Retrieved OIDC token\n")

	// Create a validator config
	validatorConfig := oidc.ValidatorConfig{
		EndpointConfig: oidc.EndpointConfig{
			Type: "githubactions",
			URL:  "https://token.actions.githubusercontent.com",
		},
		Audiences: []string{audience},
		Issuer:    "https://token.actions.githubusercontent.com",
	}

	fmt.Printf("✓ Created validator config\n")

	// Create a validator
	validator, err := oidc.NewValidatorFromConfig(&validatorConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create validator: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Created validator\n")

	// Validate the token
	claims, err := validator.ValidateToken(ctx, token.AccessToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to validate token: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Token validated successfully\n")
	fmt.Printf("  Claims: %+v\n", claims)

	fmt.Printf("\n✓ GitHub Actions OIDC validator test passed\n")
}

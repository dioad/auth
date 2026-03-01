//go:build ignore
// +build ignore

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/dioad/auth/oidc/githubactions"
)

func main() {
	// Get the audience from environment or use default
	audience := os.Getenv("OIDC_AUDIENCE")
	if audience == "" {
		audience = "https://github.com/dioad"
	}

	fmt.Printf("Testing GitHub Actions OIDC token retrieval with audience: %s\n", audience)

	// Create a token source
	tokenSource := githubactions.NewTokenSource(githubactions.WithAudience(audience))

	// Get a token
	token, err := tokenSource.Token()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get token: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Successfully retrieved OIDC token\n")
	fmt.Printf("  Token type: %s\n", token.TokenType)
	fmt.Printf("  Expiry: %s\n", token.Expiry)

	// Decode and display claims
	tokenParts := strings.Split(token.AccessToken, ".")
	if len(tokenParts) != 3 {
		fmt.Fprintf(os.Stderr, "Invalid token format\n")
		os.Exit(1)
	}

	payload, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode token payload: %v\n", err)
		os.Exit(1)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to unmarshal claims: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nToken claims:\n")
	claimsJSON, _ := json.MarshalIndent(claims, "  ", "  ")
	fmt.Printf("  %s\n", string(claimsJSON))

	// Verify expected claims
	expectedClaims := []string{"iss", "sub", "aud", "exp", "iat", "repository", "actor"}
	for _, claim := range expectedClaims {
		if _, ok := claims[claim]; !ok {
			fmt.Fprintf(os.Stderr, "Missing expected claim: %s\n", claim)
			os.Exit(1)
		}
	}

	fmt.Printf("\n✓ All expected claims present\n")
	fmt.Printf("✓ GitHub Actions OIDC client test passed\n")
}

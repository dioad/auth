package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/dioad/auth/oidc/aws"
	"github.com/dioad/auth/oidc/flyio"
	"github.com/dioad/auth/oidc/githubactions"
)

func main() {
	audience := flag.String("audience", "", "Audience for the OIDC token")
	tokenOnly := flag.Bool("token-only", false, "Output only the raw token")
	platform := flag.String("platform", "auto", "Platform to use (aws, github, flyio, auto)")
	awsSigningAlg := flag.String("aws-signing-alg", "", "AWS STS signing algorithm")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_ = ctx
	defer cancel()

	var token *oauth2.Token
	var detectedPlatform string
	var err error

	platforms := []struct {
		name   string
		source oauth2.TokenSource
	}{
		{"aws", aws.NewTokenSource(aws.WithAudience(*audience), aws.WithSigningAlgorithm(*awsSigningAlg))},
		{"github", githubactions.NewTokenSource(githubactions.WithAudience(*audience))},
		{"flyio", flyio.NewTokenSource(flyio.WithAudience(*audience))},
	}

	if *platform != "auto" {
		found := false
		for _, p := range platforms {
			if p.name == *platform {
				detectedPlatform = p.name
				token, err = p.source.Token()
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "Unknown platform: %s\n", *platform)
			os.Exit(1)
		}
	} else {
		// Auto-detection
		for _, p := range platforms {
			t, e := p.source.Token()
			if e == nil {
				token = t
				detectedPlatform = p.name
				break
			}
			// Log error if not auto-detecting or if it's a real error?
			// For auto-detect, we just move to the next.
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching token: %v\n", err)
		os.Exit(1)
	}

	if token == nil {
		fmt.Fprintf(os.Stderr, "Could not detect platform or fetch token. Ensure you are running in a supported environment.\n")
		os.Exit(1)
	}

	if *tokenOnly {
		fmt.Println(token.AccessToken)
		return
	}

	fmt.Printf("Platform: %s\n", detectedPlatform)
	fmt.Printf("Token Expiry: %v\n", token.Expiry)
	fmt.Println("\nClaims:")

	claims, err := decodeClaims(token.AccessToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding claims: %v\n", err)
		// Still print the token if we can't decode it?
		// The user might want it.
		fmt.Printf("\nRaw Token: %s\n", token.AccessToken)
		return
	}

	prettyClaims, _ := json.MarshalIndent(claims, "", "  ")
	fmt.Println(string(prettyClaims))
}

func decodeClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return claims, nil
}

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"gopkg.in/go-jose/go-jose.v2"

	"github.com/dioad/auth/oidc"
	"github.com/dioad/auth/oidc/aws"
	"github.com/dioad/auth/oidc/flyio"
	"github.com/dioad/auth/oidc/githubactions"
)

func main() {
	// Check for subcommands first.
	if len(os.Args) > 1 && os.Args[1] == "validate" {
		runValidate(os.Args[2:])
		return
	}

	audience := flag.String("audience", "", "Audience for the OIDC token")
	tokenOnly := flag.Bool("token-only", false, "Output only the raw token")
	platform := flag.String("platform", "auto", "Platform to use (aws, github, flyio, auto)")
	awsSigningAlg := flag.String("aws-signing-alg", "", "AWS STS signing algorithm")
	verify := flag.Bool("verify", false, "Verify the token signature using the platform's JWKS keys")
	flag.Parse()

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
			_, _ = fmt.Fprintf(os.Stderr, "Unknown platform: %s\n", *platform)
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
		_, _ = fmt.Fprintf(os.Stderr, "Error fetching token: %v\n", err)
		os.Exit(1)
	}

	if token == nil {
		_, _ = fmt.Fprintf(os.Stderr, "Could not detect platform or fetch token. Ensure you are running in a supported environment.\n")
		os.Exit(1)
	}

	if *tokenOnly {
		_, _ = fmt.Println(token.AccessToken)
		return
	}

	_, _ = fmt.Printf("Platform: %s\n", detectedPlatform)
	_, _ = fmt.Printf("Token Expiry: %v\n", token.Expiry)
	_, _ = fmt.Println("\nHeader:")
	header, err := decodeHeader(token.AccessToken)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error decoding header: %v\n", err)
	} else {
		printHeaderDetails(header)
	}

	_, _ = fmt.Println("\nClaims:")

	claims, err := decodeClaims(token.AccessToken)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error decoding claims: %v\n", err)
		// Still print the token if we can't decode it?
		// The user might want it.
		_, _ = fmt.Printf("\nRaw Token: %s\n", token.AccessToken)
		return
	}

	prettyClaims, _ := json.MarshalIndent(claims, "", "  ")
	_, _ = fmt.Println(string(prettyClaims))

	if *verify {
		issuer, _ := claims["iss"].(string)
		_, _ = fmt.Println("\nVerification:")
		printJWKSKeys(issuer)
		if err := verifyToken(context.Background(), token.AccessToken); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "✗ Token verification failed: %v\n", err)
			os.Exit(1)
		}
		_, _ = fmt.Println("✓ Token signature verified successfully")
	}
}

// runValidate implements the "validate" subcommand, which reads a JWT from
// stdin, decodes its claims, and verifies the token signature against the
// issuer's JWKS keys.
func runValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	issuerFlag := fs.String("issuer", "", "Override the issuer URL for JWKS discovery (default: extracted from token)")
	audienceFlag := fs.String("audience", "", "Expected audience claim to validate")
	_ = fs.Parse(args)

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "No token provided on stdin\n")
		}
		os.Exit(1)
	}
	tokenString := strings.TrimSpace(scanner.Text())

	if tokenString == "" {
		_, _ = fmt.Fprintf(os.Stderr, "No token provided on stdin\n")
		os.Exit(1)
	}

	_, _ = fmt.Println("Header:")
	header, err := decodeHeader(tokenString)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error decoding header: %v\n", err)
	} else {
		printHeaderDetails(header)
	}

	_, _ = fmt.Println("\nClaims:")
	claims, err := decodeClaims(tokenString)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error decoding claims: %v\n", err)
		_, _ = fmt.Printf("\nRaw Token: %s\n", tokenString)
		os.Exit(1)
	}

	prettyClaims, _ := json.MarshalIndent(claims, "", "  ")
	_, _ = fmt.Println(string(prettyClaims))

	_, _ = fmt.Println("\nVerification:")

	issuer := *issuerFlag
	if issuer == "" {
		iss, ok := claims["iss"].(string)
		if !ok || iss == "" {
			_, _ = fmt.Fprintf(os.Stderr, "✗ Token has no 'iss' claim; use --issuer to specify the issuer URL\n")
			os.Exit(1)
		}
		issuer = iss
	}

	printJWKSKeys(issuer)

	var audiences []string
	if *audienceFlag != "" {
		audiences = []string{*audienceFlag}
	} else {
		audiences = extractAudiences(claims)
	}

	if err := verifyTokenWithConfig(context.Background(), tokenString, issuer, audiences); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "✗ Token verification failed: %v\n", err)
		os.Exit(1)
	}
	_, _ = fmt.Println("✓ Token signature verified successfully")
}

// verifyToken extracts the issuer and audiences from the token claims and
// performs full JWKS-based signature verification.
func verifyToken(ctx context.Context, tokenString string) error {
	claims, err := decodeClaims(tokenString)
	if err != nil {
		return fmt.Errorf("decoding claims: %w", err)
	}

	issuer, ok := claims["iss"].(string)
	if !ok || issuer == "" {
		return fmt.Errorf("token has no 'iss' claim; cannot discover JWKS keys")
	}

	audiences := extractAudiences(claims)
	return verifyTokenWithConfig(ctx, tokenString, issuer, audiences)
}

// verifyTokenWithConfig performs JWKS-based signature verification for the
// given token using the supplied issuer URL and expected audiences.
func verifyTokenWithConfig(ctx context.Context, tokenString, issuer string, audiences []string) error {
	cfg := &oidc.ValidatorConfig{
		Audiences: audiences,
	}
	cfg.URL = issuer
	cfg.Issuer = issuer

	v, err := oidc.NewValidatorFromConfig(cfg)
	if err != nil {
		return fmt.Errorf("creating validator for issuer %s: %w", issuer, err)
	}

	if _, err := v.ValidateToken(ctx, tokenString); err != nil {
		return fmt.Errorf("validating token: %w", err)
	}

	return nil
}

// extractAudiences returns the audience values from decoded JWT claims.
// It handles both a single string and an array of strings for the "aud" claim.
func extractAudiences(claims map[string]any) []string {
	switch aud := claims["aud"].(type) {
	case string:
		return []string{aud}
	case []any:
		audiences := make([]string, 0, len(aud))
		for _, a := range aud {
			if s, ok := a.(string); ok {
				audiences = append(audiences, s)
			}
		}
		return audiences
	default:
		return nil
	}
}

// decodeHeader extracts the JOSE header from a JWT and returns it as a map.
func decodeHeader(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	return header, nil
}

// printHeaderDetails prints the key fields from a decoded JWT header.
func printHeaderDetails(header map[string]any) {
	if alg, ok := header["alg"].(string); ok {
		_, _ = fmt.Printf("  Algorithm: %s\n", alg)
	}
	if kid, ok := header["kid"].(string); ok {
		_, _ = fmt.Printf("  Key ID:    %s\n", kid)
	}
	if typ, ok := header["typ"].(string); ok {
		_, _ = fmt.Printf("  Type:      %s\n", typ)
	}
	// Print any extra header fields not already shown.
	for k, v := range header {
		switch k {
		case "alg", "kid", "typ":
			continue
		default:
			_, _ = fmt.Printf("  %s: %v\n", k, v)
		}
	}
}

// fetchJWKSKeys retrieves the JWKS key set from the issuer's discovery endpoint.
func fetchJWKSKeys(issuerURL string) (*jose.JSONWebKeySet, error) {
	discoveryURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"

	resp, err := http.Get(discoveryURL) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("fetching discovery document from %s: %w", discoveryURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	var config struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("decoding discovery document: %w", err)
	}
	if config.JWKSURI == "" {
		return nil, fmt.Errorf("no jwks_uri in discovery document")
	}

	jwksResp, err := http.Get(config.JWKSURI) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS from %s: %w", config.JWKSURI, err)
	}
	defer func() { _ = jwksResp.Body.Close() }()

	if jwksResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", jwksResp.StatusCode)
	}

	body, err := io.ReadAll(jwksResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading JWKS response: %w", err)
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return nil, fmt.Errorf("decoding JWKS: %w", err)
	}

	return &keySet, nil
}

// printJWKSKeys fetches and displays the JWKS keys for the given issuer.
func printJWKSKeys(issuerURL string) {
	if issuerURL == "" {
		return
	}

	keySet, err := fetchJWKSKeys(issuerURL)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "  ⚠ Could not fetch JWKS keys: %v\n", err)
		return
	}

	_, _ = fmt.Printf("  JWKS Keys (%d):\n", len(keySet.Keys))
	for i, key := range keySet.Keys {
		_, _ = fmt.Printf("    Key %d:\n", i+1)
		_, _ = fmt.Printf("      Key ID:    %s\n", key.KeyID)
		_, _ = fmt.Printf("      Algorithm: %s\n", key.Algorithm)
		_, _ = fmt.Printf("      Use:       %s\n", key.Use)
		_, _ = fmt.Printf("      Key Type:  %T\n", key.Key)
	}
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

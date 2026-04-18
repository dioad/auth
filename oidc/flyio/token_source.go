package flyio

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"golang.org/x/oauth2"
)

// CustomClaims represents the custom claims in a Fly.io OIDC token
type CustomClaims struct {
	// Fly.io specific claims
	AppId          string `json:"app_id"`
	AppName        string `json:"app_name"`
	Image          string `json:"image"`
	ImageDigest    string `json:"image_digest"`
	MachineId      string `json:"machine_id"`
	MachineName    string `json:"machine_name"`
	MachineVersion string `json:"machine_version"`
	OrgId          string `json:"org_id"`
	OrgName        string `json:"org_name"`
	Region         string `json:"region"`
}

type Claims struct {
	jwtvalidator.RegisteredClaims
	CustomClaims
}

func (c *Claims) Validate(_ context.Context) error {
	return nil
}

type tokenSource struct {
	audience     string
	client       *http.Client
	currentToken *oauth2.Token
}

type Opt func(*tokenSource)

func WithAudience(aud string) Opt {
	return func(ts *tokenSource) {
		if aud != "" {
			ts.audience = aud
		}
	}
}

type tokenPayload struct {
	Audience string `json:"aud,omitempty"`
}

// NewTokenSource: https://fly.io/docs/security/openid-connect/
func NewTokenSource(opts ...Opt) oauth2.TokenSource {
	source := &tokenSource{
		client: NewUnixSocketClient("/.fly/api"),
	}
	for _, opt := range opts {
		opt(source)
	}

	return source
}

func (ts *tokenSource) Token() (*oauth2.Token, error) {
	tokenURL := &url.URL{
		Scheme: "http",
		// The host is ignored when using a Unix socket, but it must be set to a
		// non-empty value to avoid errors in the http.Client.
		Host: "localhost",
		Path: "/v1/tokens/oidc",
	}

	payload := &tokenPayload{
		Audience: ts.audience,
	}

	payloadData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	tokenReq, err := http.NewRequest("POST", tokenURL.String(), bytes.NewReader(payloadData))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	tokenReq.Header.Set("Content-Type", "application/json")

	resp, err := ts.client.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	accessTokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return decodeToken(string(accessTokenBytes))
}

func decodeToken(accessToken string) (*oauth2.Token, error) {
	// Decode Access Token and extract expiry and any other details necessary from the token
	tokenParts := strings.Split(accessToken, ".")
	if len(tokenParts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	var tokenData map[string]any
	if err := json.Unmarshal(payload, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token payload: %w", err)
	}

	expiry, ok := tokenData["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("failed to extract expiry from token")
	}

	return &oauth2.Token{
		AccessToken: strings.TrimSpace(accessToken),
		Expiry:      time.Unix(int64(expiry), 0),
		TokenType:   "bearer",
	}, nil
}

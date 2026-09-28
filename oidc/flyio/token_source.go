package flyio

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// CustomClaims represents the custom claims in a Fly.io OIDC token.
type CustomClaims struct {
	// Fly.io specific claims
	AppID          string `json:"app_id"`
	AppName        string `json:"app_name"`
	Image          string `json:"image"`
	ImageDigest    string `json:"image_digest"`
	MachineID      string `json:"machine_id"`
	MachineName    string `json:"machine_name"`
	MachineVersion string `json:"machine_version"`
	OrgID          string `json:"org_id"`
	OrgName        string `json:"org_name"`
	Region         string `json:"region"`
}

// Claims is the JWT claims type for a Fly.io OIDC token, combining
// CustomClaims with the auth0/go-jwt-middleware CustomClaims interface.
type Claims struct {
	CustomClaims
}

// Validate implements the CustomClaims interface. Fly.io tokens carry no
// additional claims to validate.
func (c *Claims) Validate(_ context.Context) error {
	return nil
}

type tokenSource struct {
	audience string
	client   *http.Client
}

// Opt is a function option for configuring the token source.
type Opt func(*tokenSource)

// WithAudience sets the audience for the OIDC token.
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

// NewTokenSource creates a new token source for Fly.io OIDC tokens, fetched
// via the local metadata socket. See https://fly.io/docs/security/openid-connect/.
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

	tokenReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, tokenURL.String(), bytes.NewReader(payloadData))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	tokenReq.Header.Set("Content-Type", "application/json")

	resp, err := ts.client.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

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
		return nil, errors.New("invalid token format")
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
		return nil, errors.New("failed to extract expiry from token")
	}

	return &oauth2.Token{
		AccessToken: strings.TrimSpace(accessToken),
		Expiry:      time.Unix(int64(expiry), 0),
		TokenType:   "bearer",
	}, nil
}

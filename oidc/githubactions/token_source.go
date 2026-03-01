package githubactions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v2/validator"
	"golang.org/x/oauth2"
)

// CustomClaims represents the custom claims in a GitHub Actions OIDC token
type CustomClaims struct {
	// GitHub actions specific
	Actor             string `json:"actor"`
	ActorID           string `json:"actor_id"`
	BaseRef           string `json:"base_ref"`
	Environment       string `json:"environment"`
	EventName         string `json:"event_name"`
	HeadRef           string `json:"head_ref"`
	JobWorkflowRef    string `json:"job_workflow_ref"`
	Ref               string `json:"ref"`
	RefType           string `json:"ref_type"`
	Repository        string `json:"repository"`
	RepositoryID      string `json:"repository_id"`
	RepositoryOwner   string `json:"repository_owner"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	RunAttempt        string `json:"run_attempt"`
	RunID             string `json:"run_id"`
	RunNumber         string `json:"run_number"`
	RunnerEnvironment string `json:"runner_environment"`
	SHA               string `json:"sha"`
	Workflow          string `json:"workflow"`
	WorkflowRef       string `json:"workflow_ref"`
	WorkflowSHA       string `json:"workflow_sha"`
}

type Claims struct {
	jwtvalidator.RegisteredClaims
	CustomClaims
}

// Validate implements the CustomClaims interface
func (c *Claims) Validate(_ context.Context) error {
	return nil
}

type tokenSource struct {
	audience string
	client   *http.Client
	getenv   func(string) string
}

// Opt is a function option for configuring the token source
type Opt func(*tokenSource)

// WithAudience sets the audience for the OIDC token
func WithAudience(aud string) Opt {
	return func(ts *tokenSource) {
		if aud != "" {
			ts.audience = aud
		}
	}
}

// WithHTTPClient sets a custom HTTP client for the token source
func WithHTTPClient(client *http.Client) Opt {
	return func(ts *tokenSource) {
		if client != nil {
			ts.client = client
		}
	}
}

// WithEnvGetter sets a custom environment variable lookup function for the token source.
func WithEnvGetter(getter func(string) string) Opt {
	return func(ts *tokenSource) {
		if getter != nil {
			ts.getenv = getter
		}
	}
}

// NewTokenSource creates a new token source for GitHub Actions OIDC
// It retrieves tokens from the GitHub Actions OIDC provider using environment variables
// See: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
func NewTokenSource(opts ...Opt) oauth2.TokenSource {
	source := &tokenSource{
		client: http.DefaultClient,
		getenv: os.Getenv,
	}
	for _, opt := range opts {
		opt(source)
	}

	return source
}

// Token retrieves an OIDC token from GitHub Actions
func (ts *tokenSource) Token() (*oauth2.Token, error) {
	getenv := ts.getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	// Get the request token and URL from environment variables
	requestToken := getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	requestURL := getenv("ACTIONS_ID_TOKEN_REQUEST_URL")

	if requestToken == "" {
		return nil, fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable not set")
	}
	if requestURL == "" {
		return nil, fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL environment variable not set")
	}

	// Build the request URL with audience parameter if provided
	tokenURL, err := url.Parse(requestURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request URL: %w", err)
	}

	if ts.audience != "" {
		query := tokenURL.Query()
		query.Set("audience", ts.audience)
		tokenURL.RawQuery = query.Encode()
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", tokenURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+requestToken)

	// Execute the request
	resp, err := ts.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("failed to get token: status=%d (could not read response body: %w)", resp.StatusCode, readErr)
		}
		return nil, fmt.Errorf("failed to get token: status=%d, body=%s", resp.StatusCode, string(body))
	}

	// Parse the response
	var tokenResponse struct {
		Value string `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResponse.Value == "" {
		return nil, fmt.Errorf("empty token received from GitHub Actions")
	}

	return decodeToken(tokenResponse.Value)
}

// decodeToken parses a JWT token and extracts expiry information
func decodeToken(accessToken string) (*oauth2.Token, error) {
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

	// Trim any trailing whitespace from the token (including newlines)
	// This ensures the token is clean for use in Authorization headers
	return &oauth2.Token{
		AccessToken: strings.TrimSpace(accessToken),
		Expiry:      time.Unix(int64(expiry), 0),
		TokenType:   "bearer",
	}, nil
}

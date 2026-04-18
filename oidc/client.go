// Package oidc provides an OpenID Connect (OIDC) client and utilities for token validation and management.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"

	"github.com/dioad/auth/oidc/aws"
	"github.com/dioad/auth/oidc/flyio"
	"github.com/dioad/auth/oidc/githubactions"
)

var (
	ErrInvalidToken    = errors.New("invalid token")
	ErrTokenValidation = errors.New("token validation failed")
	ErrInvalidClaims   = errors.New("invalid claims format")
)

type githubActionsCustomClaims = githubactions.CustomClaims
type flyIOCustomClaims = flyio.CustomClaims
type awsCustomClaims = aws.CustomClaims

// IntrospectionResponse represents the fields returned by an RFC 7662 token introspection response,
// including some common provider extensions.
type IntrospectionResponse struct {
	ExpiresAt                           int      `json:"exp"`
	IssuedAt                            int      `json:"iat"`
	AuthTime                            int      `json:"auth_time"`
	ID                                  string   `json:"jti"`
	Issuer                              string   `json:"iss"`
	Audience                            string   `json:"aud"`
	Subject                             string   `json:"sub"`
	Type                                string   `json:"typ"`
	AuthorizedParty                     string   `json:"azp"`
	SessionID                           string   `json:"sid"`
	AuthenticationContextClassReference string   `json:"acr"`
	AllowedOrigins                      []string `json:"allowed-origins"`
	RealmAccess                         struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess struct {
		Account struct {
			Roles []string `json:"roles"`
		} `json:"account"`
	} `json:"resource_access"`
	Scope             string   `json:"scope"`
	UserPrincipalName string   `json:"upn"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
	PreferredUsername string   `json:"preferred_username"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	Email             string   `json:"email"`
	ClientId          string   `json:"client_id"`
	Username          string   `json:"username"`
	TokenType         string   `json:"token_type"`
	Active            bool     `json:"active"`
	Website           string   `json:"website"`
	Organisation      []string `json:"org"`
	flyIOCustomClaims
	githubActionsCustomClaims
	awsCustomClaims
}

// Validate satisfies the validator interface for IntrospectionResponse.
func (c *IntrospectionResponse) Validate(_ context.Context) error {
	return nil
}

// ClientOpt configures an OIDC Client.
type ClientOpt func(c *Client)

// WithClientID sets the client identifier used for OIDC flows.
func WithClientID(clientID string) ClientOpt {
	return func(c *Client) {
		c.clientID = clientID
	}
}

// WithKeyCacheTTL overrides the cache TTL for JWKS keys used during validation.
func WithKeyCacheTTL(ttl time.Duration) ClientOpt {
	return func(c *Client) {
		c.keyCacheTTL = ttl
	}
}

// WithValidatingSignatureAlgorithm sets the signature algorithm used when validating ID tokens.
func WithValidatingSignatureAlgorithm(algorithm jwtvalidator.SignatureAlgorithm) ClientOpt {
	return func(c *Client) {
		c.validatingSignatureAlgorithm = algorithm
	}
}

// WithClientIDAndSecret sets both the client ID and secret for the client.
func WithClientIDAndSecret(clientID, clientSecret string) ClientOpt {
	return func(c *Client) {
		c.clientID = clientID
		c.clientSecret = clientSecret
	}
}

type oAuth2ConfigOpt func(c *oauth2.Config)

func withScopes(scopes ...string) oAuth2ConfigOpt {
	return func(c *oauth2.Config) {
		c.Scopes = scopes
	}
}

func withClientSecret(clientSecret string) oAuth2ConfigOpt {
	return func(c *oauth2.Config) {
		c.ClientSecret = clientSecret
	}
}

func withRedirectURL(redirectURL string) oAuth2ConfigOpt {
	return func(c *oauth2.Config) {
		c.RedirectURL = redirectURL
	}
}

// WithDeviceCodeUI injects a custom device code UI handler for interactive flows.
func WithDeviceCodeUI(ui DeviceCodeUI) ClientOpt {
	return func(c *Client) {
		c.deviceUI = ui
	}
}

// WithHTTPClient sets a custom HTTP client for outbound requests.
func WithHTTPClient(doer HTTPDoer) ClientOpt {
	return func(c *Client) {
		if doer != nil {
			c.httpDoer = doer
		}
	}
}

// WithClock sets a custom clock for time-dependent behavior.
func WithClock(clock Clock) ClientOpt {
	return func(c *Client) {
		if clock != nil {
			c.clock = clock
		}
	}
}

// WithKeyFunc sets a custom key function for token validation.
func WithKeyFunc(keyFunc func(context.Context) (any, error)) ClientOpt {
	return func(c *Client) {
		if keyFunc != nil {
			c.keyFunc = keyFunc
		}
	}
}

// WithJWKSProvider sets a custom JWKS caching provider for token validation.
func WithJWKSProvider(provider *jwks.CachingProvider) ClientOpt {
	return func(c *Client) {
		if provider != nil {
			c.jwksProvider = provider
		}
	}
}

// Client represents an OIDC client.
type Client struct {
	endpoint                     Endpoint
	jwksProvider                 *jwks.CachingProvider
	keyCacheTTL                  time.Duration
	clientID                     string
	clientSecret                 string
	validatingSignatureAlgorithm jwtvalidator.SignatureAlgorithm
	deviceUI                     DeviceCodeUI
	httpDoer                     HTTPDoer
	clock                        Clock
	keyFunc                      func(context.Context) (any, error)
}

// NewClientFromConfig creates a new OIDC client from the provided configuration.
func NewClientFromConfig(config *ClientConfig) (*Client, error) {
	endpoint, err := NewEndpointFromConfig(&config.EndpointConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create new oidc endpoint: %w", err)
	}
	return NewClient(endpoint, WithClientIDAndSecret(config.ClientID, config.ClientSecret.UnmaskedString())), nil
}

// NewClient creates a new OIDC client with the provided endpoint and options.
func NewClient(endpoint Endpoint, opts ...ClientOpt) *Client {
	client := &Client{
		endpoint:                     endpoint,
		keyCacheTTL:                  5 * time.Minute,
		httpDoer:                     defaultHTTPClient(),
		clock:                        realClock{},
		validatingSignatureAlgorithm: jwtvalidator.RS256,
	}

	for _, opt := range opts {
		opt(client)
	}

	if client.jwksProvider == nil && client.keyFunc == nil {
		client.jwksProvider = jwks.NewCachingProvider(endpoint.URL(), client.keyCacheTTL)
	}
	if client.keyFunc == nil && client.jwksProvider != nil {
		client.keyFunc = client.jwksProvider.KeyFunc
	}

	return client
}

func (c *Client) Endpoint() Endpoint {
	return c.endpoint
}

func (c *Client) GothProvider(callbackURL *url.URL, scopes ...string) (goth.Provider, error) {
	ge, ok := c.endpoint.(GothEndpoint)
	if !ok {
		return nil, fmt.Errorf("endpoint does not support goth provider")
	}

	return ge.GothProvider(c.clientID, c.clientSecret, callbackURL, scopes...)
}

// oAuth2Config returns an OAuth2 configuration for the OIDC client
func (c *Client) oAuth2Config(opts ...oAuth2ConfigOpt) (*oauth2.Config, error) {
	oauth2Endpoint, err := c.endpoint.OAuth2Endpoint()
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth2 endpoint: %w", err)
	}

	config := &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint:     oauth2Endpoint,
	}

	for _, opt := range opts {
		opt(config)
	}

	return config, nil
}

// ValidateToken VerifyToke verifies the token and returns the claims
// It fetches the verification keys from the OIDC server
// and uses them to verify the token
func (c *Client) ValidateToken(ctx context.Context, token string, audiences []string) (*jwtvalidator.ValidatedClaims, error) {
	if c.keyFunc == nil && c.jwksProvider != nil {
		c.keyFunc = c.jwksProvider.KeyFunc
	}
	if c.keyFunc == nil {
		return nil, fmt.Errorf("key function not configured")
	}
	jwtValidator, err := jwtvalidator.New(
		c.keyFunc,
		c.validatingSignatureAlgorithm,
		c.endpoint.URL().String(),
		audiences,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to configure validator for %v: %w", c.endpoint.URL(), err)
	}

	validatedClaims, err := jwtValidator.ValidateToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("error validating token: %w", err)
	}

	return validatedClaims.(*jwtvalidator.ValidatedClaims), nil
}

type RequestOpt func(url.Values)

func WithAudience(audience string) RequestOpt {
	return func(v url.Values) {
		if audience != "" {
			v.Set("audience", audience)
		}
	}
}

func (c *Client) RefreshToken(ctx context.Context, refreshToken string, opts ...RequestOpt) (*oauth2.Token, error) {
	discoveredConfiguration, err := c.endpoint.DiscoveredConfiguration()
	if err != nil {
		return nil, err
	}
	tokenURL := discoveredConfiguration.TokenEndpoint
	if tokenURL == "" {
		return nil, fmt.Errorf("token endpoint not available")
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)

	for _, opt := range opts {
		opt(data)
	}

	tokenResponse, err := doPost[tokenJSON](ctx, c.httpDoer, tokenURL, data)
	if err != nil {
		return nil, err
	}

	return tokenResponse.toToken(c.clock.Now()), nil
}

// AuthorizationCodeRedirectFlow generates the authorization URL for the Authorization Code Flow
// TODO: figure out a better name
func (c *Client) AuthorizationCodeRedirectFlow(ctx context.Context, state string, scopes []string, redirectURI string, opts ...RequestOpt) (string, error) {
	discoveredConfiguration, err := c.endpoint.DiscoveredConfiguration()
	if err != nil {
		return "", err
	}
	authURL := discoveredConfiguration.AuthorizationEndpoint
	if authURL == "" {
		return "", fmt.Errorf("authorization endpoint not available")
	}

	data := url.Values{}
	data.Set("response_type", "code")
	data.Set("client_id", c.clientID)
	data.Set("redirect_uri", redirectURI)

	// TODO extract this to request parameter?
	data.Set("scope", strings.Join(scopes, " "))
	data.Set("state", state)

	for _, opt := range opts {
		opt(data)
	}

	authURLWithParams := authURL + "?" + data.Encode()
	return authURLWithParams, nil
}

func (c *Client) AuthorizationCodeToken(ctx context.Context, code string, redirect_uri string, opts ...RequestOpt) (*oauth2.Token, error) {
	discoveredConfiguration, err := c.endpoint.DiscoveredConfiguration()
	if err != nil {
		return nil, err
	}
	tokenURL := discoveredConfiguration.TokenEndpoint
	if tokenURL == "" {
		return nil, fmt.Errorf("token endpoint not available")
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)

	// data.Set("grant_type", "authorization_code")
	// data.Set("code", code)
	data.Set("redirect_uri", redirect_uri)
	// data.Set("client_id", h.Config.ClientID)
	// data.Set("client_secret", h.Config.ClientSecret)

	for _, opt := range opts {
		opt(data)
	}

	tokenResponse, err := doPost[tokenJSON](ctx, c.httpDoer, tokenURL, data)
	if err != nil {
		return nil, err
	}

	return tokenResponse.toToken(c.clock.Now()), nil
}

type RefreshingClientCredentialsTokenSource struct {
	client *Client
	ctx    context.Context
	opts   []RequestOpt
	clock  Clock

	mu           sync.Mutex // to ensure thread safety
	currentToken *oauth2.Token
}

func (ts *RefreshingClientCredentialsTokenSource) Token() (*oauth2.Token, error) {
	clock := ts.clock
	if clock == nil {
		clock = realClock{}
	}
	var err error
	if ts.currentToken == nil {
		ts.mu.Lock()
		defer ts.mu.Unlock()

		ts.currentToken, err = ts.client.ClientCredentialsToken(ts.ctx, ts.opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to get client credentials token: %w", err)
		}
	} else {
		// If the token is expired, refresh it
		if ts.currentToken.Expiry.Before(clock.Now()) {
			ts.mu.Lock()
			defer ts.mu.Unlock()

			// Double-check if the token is still valid after acquiring the lock
			if ts.currentToken.Expiry.Before(clock.Now()) {
				ts.currentToken, err = ts.client.ClientCredentialsToken(ts.ctx, ts.opts...)
				if err != nil {
					return nil, fmt.Errorf("failed to refresh client credentials token: %w", err)
				}
			}
		}
	}

	return ts.currentToken, nil
	// return ts.client.ClientCredentialsToken(ts.ctx, ts.opts...)
}

func (c *Client) RefreshingClientCredentialsToken(ctx context.Context, opts ...RequestOpt) (oauth2.TokenSource, error) {
	// token, err := c.ClientCredentialsToken(ctx, opts...)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get client credentials token: %w", err)
	// }
	//
	// if token.AccessToken == "" {
	// 	return nil, fmt.Errorf("client credentials token is empty")
	// }

	return &RefreshingClientCredentialsTokenSource{
		client: c,
		ctx:    ctx,
		opts:   opts,
		clock:  c.clock,
	}, nil
}

// ClientCredentialsToken gets a token using the client_credentials grant
// It sends the client_id and client_secret to the token endpoint
// and gets a token in response
func (c *Client) ClientCredentialsToken(ctx context.Context, opts ...RequestOpt) (*oauth2.Token, error) {
	discoveredConfiguration, err := c.endpoint.DiscoveredConfiguration()
	if err != nil {
		return nil, err
	}
	tokenURL := discoveredConfiguration.TokenEndpoint
	if tokenURL == "" {
		return nil, fmt.Errorf("token endpoint not available")
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)

	for _, opt := range opts {
		opt(data)
	}

	tokenResponse, err := doPost[tokenJSON](ctx, c.httpDoer, tokenURL, data)
	if err != nil {
		return nil, err
	}

	return tokenResponse.toToken(c.clock.Now()), nil
}

// IntrospectToken introspects the token
// It sends the token to the introspection endpoint
// and gets the response
func (c *Client) IntrospectToken(ctx context.Context, token string) (*IntrospectionResponse, error) {
	discoveredConfiguration, err := c.endpoint.DiscoveredConfiguration()
	if err != nil {
		return nil, err
	}
	introspectionURL := discoveredConfiguration.IntrospectionEndpoint
	if introspectionURL == "" {
		return nil, fmt.Errorf("introspection endpoint not available")
	}

	data := url.Values{}
	data.Set("token", token)

	introspectionResponse, err := doPostWithBasicAuth[IntrospectionResponse](ctx, c.httpDoer, introspectionURL, data, c.clientID, c.clientSecret)
	if err != nil {
		return nil, err
	}

	return introspectionResponse, nil
}

func (c *Client) DeviceToken(ctx context.Context, scopes ...string) (*oauth2.Token, error) {
	config, err := c.oAuth2Config(withScopes(scopes...))
	if err != nil {
		return nil, fmt.Errorf("error getting OAuth2 config: %w", err)
	}

	verifier := oauth2.GenerateVerifier()

	deviceCode, err := config.DeviceAuth(ctx, oauth2.S256ChallengeOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("error getting device code: %w", err)
	}

	deviceCodeUI := DeviceCodeUIConsoleText
	if c.deviceUI != nil {
		deviceCodeUI = c.deviceUI
	}

	err = deviceCodeUI(deviceCode)
	if err != nil {
		return nil, fmt.Errorf("error displaying device code: %w", err)
	}

	token, err := config.DeviceAccessToken(ctx, deviceCode, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("error exchanging device code for access token: %w", err)
	}

	return token, err
}

func (c *Client) HTTPClient(ctx context.Context, t *oauth2.Token) (*http.Client, error) {
	oauth2Config, err := c.oAuth2Config()
	if err != nil {
		return nil, fmt.Errorf("error getting OAuth2 config: %w", err)
	}
	return oauth2Config.Client(ctx, t), nil
}

func (c *Client) TokenSource(t *oauth2.Token) (oauth2.TokenSource, error) {
	oauth2Config, err := c.oAuth2Config()
	if err != nil {
		return nil, fmt.Errorf("error getting OAuth2 config: %w", err)
	}
	return oauth2Config.TokenSource(context.Background(), t), nil
}

func ExtractClaims[T jwtvalidator.CustomClaims](claims any) (jwtvalidator.RegisteredClaims, T, error) {
	var zeroCustomClaims T
	var zeroRegisteredClaims jwtvalidator.RegisteredClaims

	validatedClaims, ok := claims.(*jwtvalidator.ValidatedClaims)
	if !ok {
		return zeroRegisteredClaims, zeroCustomClaims,
			fmt.Errorf("error extracting claims")
	}

	if validatedClaims.CustomClaims == nil {
		return validatedClaims.RegisteredClaims, zeroCustomClaims, nil
	}

	customClaims, ok := validatedClaims.CustomClaims.(T)
	if !ok {
		return validatedClaims.RegisteredClaims, zeroCustomClaims,
			fmt.Errorf("%w: expected custom claims type %T, got %T",
				ErrInvalidClaims, zeroCustomClaims, validatedClaims.CustomClaims)
	}

	return validatedClaims.RegisteredClaims, customClaims, nil
}

type tokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

func (tr *tokenJSON) toToken(now time.Time) *oauth2.Token {
	t := &oauth2.Token{
		AccessToken:  tr.AccessToken,
		TokenType:    tr.TokenType,
		RefreshToken: tr.RefreshToken,
	}
	if tr.ExpiresIn > 0 {
		t.Expiry = now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	if tr.IDToken != "" {
		t = t.WithExtra(map[string]any{"id_token": tr.IDToken})
	}
	return t
}

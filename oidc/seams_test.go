package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/dioad/auth/oidc"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type recordingDoer struct {
	requests []*http.Request
	response *http.Response
	err      error
}

func (d *recordingDoer) Do(req *http.Request) (*http.Response, error) {
	d.requests = append(d.requests, req)
	return d.response, d.err
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

type memoryTokenStore struct {
	token     *oauth2.Token
	loadCount int
	saveCount int
}

func (s *memoryTokenStore) LoadToken(_ context.Context) (*oauth2.Token, error) {
	s.loadCount++
	return s.token, nil
}

func (s *memoryTokenStore) SaveToken(_ context.Context, token *oauth2.Token) error {
	s.saveCount++
	s.token = token
	return nil
}

func TestEndpointDiscoveryUsesHTTPDoer(t *testing.T) {
	body := `{"authorization_endpoint":"https://auth","token_endpoint":"https://token","device_authorization_endpoint":"https://device"}`
	doer := &recordingDoer{
		response: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
		},
	}

	endpoint, err := oidc.NewEndpoint("https://issuer.example", oidc.WithHTTPDoer(doer))
	require.NoError(t, err)

	config, err := endpoint.DiscoveredConfiguration()
	require.NoError(t, err)
	assert.Equal(t, "https://auth", config.AuthorizationEndpoint)
	assert.Len(t, doer.requests, 1)
}

func TestClientValidateTokenWithKeyFunc(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuer := "https://issuer.example"
	claims := jwtv5.MapClaims{
		"iss": issuer,
		"sub": "test-user",
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)

	endpoint, err := oidc.NewEndpoint(issuer)
	require.NoError(t, err)
	client := oidc.NewClient(
		endpoint,
		oidc.WithKeyFunc(func(_ context.Context) (any, error) {
			return &key.PublicKey, nil
		}),
		oidc.WithValidatingSignatureAlgorithm(jwtvalidator.RS256),
	)

	validatedClaims, err := client.ValidateToken(t.Context(), tokenString, []string{"test-audience"})
	require.NoError(t, err)
	assert.Equal(t, "test-user", validatedClaims.RegisteredClaims.Subject)
}

func TestFileTokenSourceUsesStoreAndClock(t *testing.T) {
	now := time.Date(2025, 2, 1, 12, 0, 0, 0, time.UTC)
	store := &memoryTokenStore{
		token: &oauth2.Token{
			AccessToken: "stored-token",
			Expiry:      now.Add(time.Hour),
		},
	}
	clock := fixedClock{now: now}

	source, err := oidc.NewTokenSourceFromConfigWithFactories(
		oidc.ClientConfig{TokenFile: "ignored"},
		map[string]oidc.TokenSourceFactory{},
		store,
		clock,
		t.Context(),
	)
	require.NoError(t, err)
	require.NotNil(t, source)

	resolved, err := source.Token()
	require.NoError(t, err)
	assert.Equal(t, "stored-token", resolved.AccessToken)
	assert.Equal(t, 1, store.loadCount)
	assert.Equal(t, 0, store.saveCount)
}

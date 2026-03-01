package testutil

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/go-jose/go-jose.v2"
)

func TestMockIdPDiscovery(t *testing.T) {
	idp, err := NewMockIdP()
	require.NoError(t, err)
	t.Cleanup(idp.Close)

	resp, err := http.Get(idp.Issuer + "/.well-known/openid-configuration")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var config map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&config))

	assert.Equal(t, idp.Issuer, config["issuer"])
	assert.Equal(t, idp.Issuer+"/authorize", config["authorization_endpoint"])
	assert.Equal(t, idp.Issuer+"/token", config["token_endpoint"])
	assert.Equal(t, idp.Issuer+"/userinfo", config["userinfo_endpoint"])
	assert.Equal(t, idp.Issuer+"/jwks.json", config["jwks_uri"])
}

func TestMockIdPJWKS(t *testing.T) {
	idp, err := NewMockIdP()
	require.NoError(t, err)
	t.Cleanup(idp.Close)

	resp, err := http.Get(idp.Issuer + "/jwks.json")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var keys jose.JSONWebKeySet
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&keys))

	if assert.Len(t, keys.Keys, 1) {
		assert.Equal(t, "test-key", keys.Keys[0].KeyID)
		assert.Equal(t, string(jose.RS256), keys.Keys[0].Algorithm)
		assert.Equal(t, "sig", keys.Keys[0].Use)
	}
}

func TestMockIdPAuthorizeRedirect(t *testing.T) {
	idp, err := NewMockIdP()
	require.NoError(t, err)
	t.Cleanup(idp.Close)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	redirectURI := "https://example.com/callback"
	req, err := http.NewRequest("GET", idp.Issuer+"/authorize", nil)
	require.NoError(t, err)

	query := req.URL.Query()
	query.Set("redirect_uri", redirectURI)
	query.Set("state", "state-123")
	req.URL.RawQuery = query.Encode()

	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.Contains(t, location, redirectURI)
	assert.Contains(t, location, "state=state-123")
	assert.Contains(t, location, "code=")
}

func TestMockIdPTokenResponse(t *testing.T) {
	idp, err := NewMockIdP()
	require.NoError(t, err)
	t.Cleanup(idp.Close)

	resp, err := http.Post(idp.Issuer+"/token", "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokenResp))

	accessToken, ok := tokenResp["access_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, accessToken)

	parsed, err := jwt.Parse(accessToken, func(t *jwt.Token) (any, error) {
		return &idp.Key.PublicKey, nil
	})
	require.NoError(t, err)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, idp.Issuer, claims["iss"])
	assert.Equal(t, "test-user", claims["sub"])
	assert.Equal(t, "test-client", claims["aud"])
	assert.Equal(t, "test@example.com", claims["email"])
}

func TestMockIdPUserInfo(t *testing.T) {
	idp, err := NewMockIdP()
	require.NoError(t, err)
	t.Cleanup(idp.Close)

	resp, err := http.Get(idp.Issuer + "/userinfo")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var user map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&user))

	assert.Equal(t, "test-user", user["sub"])
	assert.Equal(t, "test@example.com", user["email"])
	assert.Equal(t, "Test User", user["name"])
}

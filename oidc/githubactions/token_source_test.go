package githubactions

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeToken(t *testing.T) {
	now := time.Now().Unix()
	claims := map[string]any{
		"sub":        "repo:org/repo:ref:refs/heads/main",
		"exp":        float64(now + 3600),
		"repository": "org/repo",
	}

	payload, _ := json.Marshal(claims)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payload)
	tokenString := fmt.Sprintf("header.%s.signature", payloadEncoded)

	token, err := decodeToken(tokenString)
	assert.NoError(t, err)
	assert.Equal(t, tokenString, token.AccessToken)
	assert.Equal(t, time.Unix(now+3600, 0).Unix(), token.Expiry.Unix())
}

func TestDecodeToken_Invalid(t *testing.T) {
	_, err := decodeToken("not.a.jwt")
	assert.Error(t, err)
}

func TestTokenUsesEnvGetterAndHTTPClient(t *testing.T) {
	now := time.Now().Unix()
	claims := map[string]any{"exp": float64(now + 3600)}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payload)
	tokenString := fmt.Sprintf("header.%s.signature", payloadEncoded)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer request-token", r.Header.Get("Authorization"))
		assert.Equal(t, "audience", r.URL.Query().Get("audience"))
		_ = json.NewEncoder(w).Encode(map[string]any{"value": tokenString})
	}))
	defer server.Close()

	env := func(key string) string {
		switch key {
		case "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
			return "request-token"
		case "ACTIONS_ID_TOKEN_REQUEST_URL":
			return server.URL
		default:
			return ""
		}
	}

	tokenSource := NewTokenSource(
		WithAudience("audience"),
		WithHTTPClient(server.Client()),
		WithEnvGetter(env),
	)

	token, err := tokenSource.Token()
	require.NoError(t, err)
	assert.Equal(t, tokenString, token.AccessToken)
	assert.Equal(t, time.Unix(now+3600, 0).Unix(), token.Expiry.Unix())
}

func TestTokenMissingEnvVars(t *testing.T) {
	tokenSource := NewTokenSource(WithEnvGetter(func(string) string { return "" }))

	_, err := tokenSource.Token()
	assert.Error(t, err)
}

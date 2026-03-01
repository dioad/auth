package flyio

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDecodeToken(t *testing.T) {
	now := time.Now().Unix()
	claims := map[string]any{
		"sub":    "fly-machine-123",
		"exp":    float64(now + 3600),
		"app_id": "my-app",
	}

	payload, _ := json.Marshal(claims)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payload)
	tokenString := fmt.Sprintf("header.%s.signature", payloadEncoded)

	token, err := decodeToken(tokenString)
	assert.NoError(t, err)
	assert.Equal(t, tokenString, token.AccessToken)
	assert.Equal(t, time.Unix(now+3600, 0).Unix(), token.Expiry.Unix())
	assert.Equal(t, "bearer", token.TokenType)
}

func TestDecodeToken_Invalid(t *testing.T) {
	_, err := decodeToken("invalid-token")
	assert.Error(t, err)

	_, err = decodeToken("a.b")
	assert.Error(t, err)
}

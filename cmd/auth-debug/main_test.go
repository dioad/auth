package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeClaims(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		// Header: {"alg":"HS256","typ":"JWT"}
		// Payload: {"sub":"1234567890","iss":"https://example.com","aud":"my-api","name":"Test"}
		// Signature: dummy
		token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsImF1ZCI6Im15LWFwaSIsIm5hbWUiOiJUZXN0In0.signature"

		claims, err := decodeClaims(token)
		require.NoError(t, err)
		assert.Equal(t, "1234567890", claims["sub"])
		assert.Equal(t, "https://example.com", claims["iss"])
		assert.Equal(t, "my-api", claims["aud"])
		assert.Equal(t, "Test", claims["name"])
	})

	t.Run("invalid format", func(t *testing.T) {
		_, err := decodeClaims("not-a-jwt")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token format")
	})

	t.Run("invalid base64 payload", func(t *testing.T) {
		_, err := decodeClaims("header.!!!invalid!!!.signature")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode payload")
	})

	t.Run("invalid JSON payload", func(t *testing.T) {
		// "bm90LWpzb24" is base64url for "not-json"
		_, err := decodeClaims("header.bm90LWpzb24.signature")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal claims")
	})
}

func TestExtractAudiences(t *testing.T) {
	t.Run("string audience", func(t *testing.T) {
		claims := map[string]any{"aud": "my-api"}
		auds := extractAudiences(claims)
		assert.Equal(t, []string{"my-api"}, auds)
	})

	t.Run("array audience", func(t *testing.T) {
		claims := map[string]any{"aud": []any{"api-1", "api-2"}}
		auds := extractAudiences(claims)
		assert.Equal(t, []string{"api-1", "api-2"}, auds)
	})

	t.Run("no audience", func(t *testing.T) {
		claims := map[string]any{"sub": "user"}
		auds := extractAudiences(claims)
		assert.Nil(t, auds)
	})

	t.Run("unexpected type", func(t *testing.T) {
		claims := map[string]any{"aud": 12345}
		auds := extractAudiences(claims)
		assert.Nil(t, auds)
	})

	t.Run("mixed array types", func(t *testing.T) {
		claims := map[string]any{"aud": []any{"valid", 42, "also-valid"}}
		auds := extractAudiences(claims)
		assert.Equal(t, []string{"valid", "also-valid"}, auds)
	})
}

func TestDecodeHeader(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		// Header: {"alg":"HS256","typ":"JWT"}
		token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"

		header, err := decodeHeader(token)
		require.NoError(t, err)
		assert.Equal(t, "HS256", header["alg"])
		assert.Equal(t, "JWT", header["typ"])
	})

	t.Run("header with kid", func(t *testing.T) {
		// Header: {"alg":"RS256","typ":"JWT","kid":"my-key-id"}
		// base64url("{"alg":"RS256","typ":"JWT","kid":"my-key-id"}") = eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im15LWtleS1pZCJ9
		token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im15LWtleS1pZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"

		header, err := decodeHeader(token)
		require.NoError(t, err)
		assert.Equal(t, "RS256", header["alg"])
		assert.Equal(t, "JWT", header["typ"])
		assert.Equal(t, "my-key-id", header["kid"])
	})

	t.Run("invalid format", func(t *testing.T) {
		_, err := decodeHeader("not-a-jwt")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token format")
	})

	t.Run("invalid base64 header", func(t *testing.T) {
		_, err := decodeHeader("!!!invalid!!!.payload.signature")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode header")
	})

	t.Run("invalid JSON header", func(t *testing.T) {
		// "bm90LWpzb24" is base64url for "not-json"
		_, err := decodeHeader("bm90LWpzb24.payload.signature")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal header")
	})
}

func TestVerifyToken_NoIssClaim(t *testing.T) {
	// Token payload: {"sub":"1234567890","name":"Test"} (no iss claim)
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QifQ.signature"

	err := verifyToken(t.Context(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no 'iss' claim")
}

func TestVerifyToken_InvalidFormat(t *testing.T) {
	err := verifyToken(t.Context(), "not-a-jwt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding claims")
}

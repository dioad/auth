package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"maps"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func signTestToken(t *testing.T, key *rsa.PrivateKey, issuer string, audiences []string, claims map[string]any) string {
	t.Helper()

	allClaims := jwt.MapClaims{
		"iss": issuer,
		"aud": audiences,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
	maps.Copy(allClaims, claims)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, allClaims)
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

func TestNewValidatorFromConfigWithKeyFunc(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tokenString := signTestToken(t, key, "https://issuer.example", []string{"aud"}, map[string]any{"role": "admin"})

	cfg := ValidatorConfig{
		Issuer:    "https://issuer.example",
		Audiences: []string{"aud"},
	}

	v, err := NewValidatorFromConfigWithOptions(&cfg, WithValidatorKeyFunc(func(ctx context.Context) (any, error) {
		return &key.PublicKey, nil
	}))
	require.NoError(t, err)

	claims, err := v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err)
	require.NotNil(t, claims)
}

func TestValidatorClaimPredicate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tokenString := signTestToken(t, key, "https://issuer.example", []string{"aud"}, map[string]any{"role": "admin"})

	cfg := ValidatorConfig{
		Issuer:         "https://issuer.example",
		Audiences:      []string{"aud"},
		ClaimPredicate: map[string]any{"role": "admin"},
	}

	v, err := NewValidatorFromConfigWithOptions(&cfg, WithValidatorKeyFunc(func(ctx context.Context) (any, error) {
		return &key.PublicKey, nil
	}))
	require.NoError(t, err)

	_, err = v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err)

	cfg.ClaimPredicate = map[string]any{"role": "user"}
	v, err = NewValidatorFromConfigWithOptions(&cfg, WithValidatorKeyFunc(func(ctx context.Context) (any, error) {
		return &key.PublicKey, nil
	}))
	require.NoError(t, err)

	_, err = v.ValidateToken(context.Background(), tokenString)
	require.Error(t, err)
}

func TestMultiValidatorFallsBack(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tokenString := signTestToken(t, key2, "https://issuer.example", []string{"aud"}, map[string]any{"role": "admin"})

	badValidator, err := NewValidatorFromConfigWithOptions(
		&ValidatorConfig{Issuer: "https://issuer.example", Audiences: []string{"aud"}},
		WithValidatorKeyFunc(func(ctx context.Context) (any, error) { return &key1.PublicKey, nil }),
	)
	require.NoError(t, err)

	goodValidator, err := NewValidatorFromConfigWithOptions(
		&ValidatorConfig{Issuer: "https://issuer.example", Audiences: []string{"aud"}},
		WithValidatorKeyFunc(func(ctx context.Context) (any, error) { return &key2.PublicKey, nil }),
	)
	require.NoError(t, err)

	mv := &MultiValidator{Validators: []TokenValidator{badValidator, goodValidator}}

	claims, err := mv.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err)
	require.NotNil(t, claims)
}

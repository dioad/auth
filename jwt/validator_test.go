package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"testing"
	"time"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
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

func FuzzDecodeTokenData(f *testing.F) {
	// A sample JWT-like string (header.payload.signature)
	f.Add("header.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature")
	f.Fuzz(func(t *testing.T, token string) {
		got, err := decodeTokenData(token)
		if err != nil {
			return
		}
		if got == nil {
			t.Errorf("decodeTokenData(%q) returned nil with no error", token)
		}
	})
}

func TestDecodeTokenData(t *testing.T) {
	now := time.Now().Unix()
	claims := map[string]any{
		"sub": "1234567890",
		"exp": float64(now + 3600),
		"iat": float64(now),
		"nbf": float64(now),
	}

	payload, err := json.Marshal(claims)
	require.NoError(t, err, "failed to marshal claims")
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payload)
	tokenString := fmt.Sprintf("header.%s.signature", payloadEncoded)

	data, err := decodeTokenData(tokenString)
	require.NoError(t, err, "decodeTokenData failed")

	dataMap, ok := data.(map[string]any)
	require.True(t, ok)

	assert.Equal(t, "1234567890", dataMap["sub"])
	assert.NotNil(t, dataMap["exp_datetime"])
	assert.NotNil(t, dataMap["iat_datetime"])
	assert.NotNil(t, dataMap["nbf_datetime"])
}

func TestPredicateValidator(t *testing.T) {
	mockParent := &mockValidator{
		claims: map[string]any{"sub": "123"},
	}

	predicate := &ClaimKey{Key: "org", Value: "my-org"}
	validator := &PredicateValidator{ParentValidator: mockParent, Predicate: predicate}

	// Valid token with matching claim
	claims := jwt.MapClaims{"org": "my-org"}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("secret"))

	got, err := validator.ValidateToken(context.Background(), tokenString)
	assert.NoError(t, err)
	assert.Equal(t, mockParent.claims, got)

	// Valid token with non-matching claim
	claims2 := jwt.MapClaims{"org": "other-org"}
	token2 := jwt.NewWithClaims(jwt.SigningMethodHS256, claims2)
	tokenString2, _ := token2.SignedString([]byte("secret"))

	_, err = validator.ValidateToken(context.Background(), tokenString2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "predicate validation failed")
}

func TestPredicateValidatorWithValidatedClaimsFallback(t *testing.T) {
	// When extractClaimsMap fails (invalid token string), the predicate validator
	// should fall back to building mapClaims from *jwtvalidator.ValidatedClaims.
	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "user-123",
			Issuer:  "https://issuer.example",
		},
	}
	mockParent := &mockValidator{claims: vc}

	predicate := &ClaimKey{Key: "sub", Value: "user-123"}
	validator := &PredicateValidator{ParentValidator: mockParent, Predicate: predicate}

	// Use an invalid token string so that extractClaimsMap fails, forcing the fallback.
	got, err := validator.ValidateToken(context.Background(), "not.a.valid.jwt")
	assert.NoError(t, err)
	assert.Equal(t, vc, got)

	// Predicate that does not match should still fail.
	predicate2 := &ClaimKey{Key: "sub", Value: "other-user"}
	validator2 := &PredicateValidator{ParentValidator: mockParent, Predicate: predicate2}

	_, err = validator2.ValidateToken(context.Background(), "not.a.valid.jwt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "predicate validation failed")
}


func TestMultiValidator(t *testing.T) {
	v1 := &mockValidator{err: fmt.Errorf("fail 1")}
	v2 := &mockValidator{claims: "success 2"}

	mv := NewMultiValidator(v1, v2)

	claims, err := mv.ValidateToken(context.Background(), "some-token")
	assert.NoError(t, err)
	assert.Equal(t, "success 2", claims)

	v3 := &mockValidator{err: fmt.Errorf("fail 3")}
	mv2 := NewMultiValidator(v1, v3)
	_, err = mv2.ValidateToken(context.Background(), "some-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token validation failed")
}

type mockValidator struct {
	claims any
	err    error
}

func (m *mockValidator) ValidateToken(ctx context.Context, tokenString string) (any, error) {
	return m.claims, m.err
}

func (m *mockValidator) String() string {
	return "mock"
}

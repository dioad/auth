package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"testing"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/jwks"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
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
	token.Header["kid"] = "test-key"
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

// TestResolveAllowedClockSkew_DefaultsToOneMinute is also the regression test
// for the drift between jwt and oidc's validator builders: oidc previously
// passed cfg.AllowedClockSkew straight through with no default, so an
// unconfigured oidc.ValidatorConfig got zero tolerance while an unconfigured
// jwt.ValidatorConfig got one minute. Both now go through this shared
// resolver.
func TestResolveAllowedClockSkew_DefaultsToOneMinute(t *testing.T) {
	require.Equal(t, time.Minute, ResolveAllowedClockSkew(0))
	require.Equal(t, time.Minute, ResolveAllowedClockSkew(-5))
}

func TestResolveAllowedClockSkew_PreservesExplicitValue(t *testing.T) {
	require.Equal(t, 30*time.Second, ResolveAllowedClockSkew(30))
}

func TestNewValidatorFromConfigWithKeyFunc(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tokenString := signTestToken(t, key, "https://issuer.example", []string{"aud"}, map[string]any{"role": "admin"})

	cfg := ValidatorConfig{
		Issuer:             "https://issuer.example",
		Audiences:          []string{"aud"},
		SignatureAlgorithm: "RS256",
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
		Issuer:             "https://issuer.example",
		Audiences:          []string{"aud"},
		SignatureAlgorithm: "RS256",
		ClaimPredicate:     map[string]any{"role": "admin"},
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

func TestNewValidatorFromConfigWithMultipleSignatureAlgorithms(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tokenString := signTestToken(t, key, "https://issuer.example", []string{"aud"}, map[string]any{"role": "admin"})

	jwkKey, err := jwk.Import(&key.PublicKey)
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.KeyIDKey, "test-key"))
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, "RS256"))
	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(jwkKey))

	cfg := ValidatorConfig{
		Issuer:              "https://issuer.example",
		Audiences:           []string{"aud"},
		SignatureAlgorithms: []string{"RS256", "ES384"},
	}

	v, err := NewValidatorFromConfigWithOptions(&cfg, WithValidatorKeyFunc(func(context.Context) (any, error) {
		return keySet, nil
	}))
	require.NoError(t, err)

	claims, err := v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err)
	require.NotNil(t, claims)
}

func TestNewValidatorFromConfigRejectsInvalidSignatureAlgorithms(t *testing.T) {
	cfg := ValidatorConfig{
		Issuer:              "https://issuer.example",
		Audiences:           []string{"aud"},
		SignatureAlgorithms: []string{"RS256", "INVALID"},
	}

	_, err := NewValidatorFromConfigWithOptions(&cfg, WithValidatorKeyFunc(func(context.Context) (any, error) {
		return "unused", nil
	}))
	require.Error(t, err)
}

func TestMultiValidatorFallsBack(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tokenString := signTestToken(t, key2, "https://issuer.example", []string{"aud"}, map[string]any{"role": "admin"})

	badValidator, err := NewValidatorFromConfigWithOptions(
		&ValidatorConfig{Issuer: "https://issuer.example", Audiences: []string{"aud"}, SignatureAlgorithm: "RS256"},
		WithValidatorKeyFunc(func(ctx context.Context) (any, error) { return &key1.PublicKey, nil }),
	)
	require.NoError(t, err)

	goodValidator, err := NewValidatorFromConfigWithOptions(
		&ValidatorConfig{Issuer: "https://issuer.example", Audiences: []string{"aud"}, SignatureAlgorithm: "RS256"},
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
		assert.NotNil(t, got, "decodeTokenData(%q) returned nil with no error", token)
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
	// Pin the exact converted time, not just non-nil: time.Unix(sec, 0) with
	// the nanosecond argument mutated to ±1 would still produce a non-nil
	// time.Time that NotNil can't distinguish from the correct one.
	assert.Equal(t, time.Unix(now+3600, 0), dataMap["exp_datetime"])
	assert.Equal(t, time.Unix(now, 0), dataMap["iat_datetime"])
	assert.Equal(t, time.Unix(now, 0), dataMap["nbf_datetime"])
}

func TestDecodeTokenData_RejectsWrongSegmentCount(t *testing.T) {
	_, err := decodeTokenData("only-one-segment")
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid token format")
}

func TestDecodeTokenData_RejectsInvalidBase64Payload(t *testing.T) {
	_, err := decodeTokenData("header.not-valid-base64!!!.signature")
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to decode token payload")
}

func TestDecodeTokenData_RejectsInvalidJSONPayload(t *testing.T) {
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	tokenString := fmt.Sprintf("header.%s.signature", payloadEncoded)

	_, err := decodeTokenData(tokenString)
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to unmarshal token payload")
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

func TestNewValidatorFromConfigWithOptions_RejectsNilConfig(t *testing.T) {
	_, err := NewValidatorFromConfigWithOptions(nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "validator config is nil")
}

func TestNewValidatorFromConfigWithOptions_RequiresIssuer(t *testing.T) {
	cfg := ValidatorConfig{
		Audiences:          []string{"aud"},
		SignatureAlgorithm: "RS256",
	}

	_, err := NewValidatorFromConfigWithOptions(&cfg, WithValidatorKeyFunc(func(context.Context) (any, error) {
		return "unused", nil
	}))
	require.Error(t, err)
	assert.ErrorContains(t, err, "issuer must be provided")
}

// TestNewValidatorFromConfigWithOptions_WrapsSignatureAlgorithmResolutionError
// verifies both that an invalid signature-algorithm entry is rejected, and
// that the error is wrapped (not just stringified) so callers can unwrap it.
func TestNewValidatorFromConfigWithOptions_WrapsSignatureAlgorithmResolutionError(t *testing.T) {
	cfg := ValidatorConfig{
		Issuer:              "https://issuer.example",
		Audiences:           []string{"aud"},
		SignatureAlgorithms: []string{""},
	}

	_, err := NewValidatorFromConfigWithOptions(&cfg, WithValidatorKeyFunc(func(context.Context) (any, error) {
		return "unused", nil
	}))
	require.Error(t, err)
	assert.ErrorContains(t, err, "resolving signature algorithms")

	inner := errors.Unwrap(err)
	require.NotNil(t, inner, "the underlying signature-algorithm error must be unwrappable, not just interpolated into the message")
	assert.ErrorContains(t, inner, "signature_algorithms[0] must not be empty")
}

// TestNewValidatorFromConfigWithOptions_PropagatesKeyFuncResolutionError pins
// the error path when no WithValidatorKeyFunc is supplied and key resolution
// itself fails (here, via an issuer that url.Parse rejects), verifying
// ResolveKeyFunc's error reaches the caller rather than being swallowed.
func TestNewValidatorFromConfigWithOptions_PropagatesKeyFuncResolutionError(t *testing.T) {
	cfg := ValidatorConfig{
		Issuer:             "https://issuer.example/\x7f",
		Audiences:          []string{"aud"},
		SignatureAlgorithm: "RS256",
	}

	_, err := NewValidatorFromConfigWithOptions(&cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid issuer URL")
}

// TestResolveKeyFunc_ReusesExplicitProvider covers the pre-existing-provider
// guard: when a provider is already supplied, it must be returned as-is --
// including when the issuer argument doesn't even match the provider's own
// issuer, proving the issuer argument is genuinely ignored in that case,
// not just coincidentally consistent.
func TestResolveKeyFunc_ReusesExplicitProvider(t *testing.T) {
	issuerURL, err := url.Parse("https://provider-issuer.example")
	require.NoError(t, err)
	provider, err := jwks.NewCachingProvider(jwks.WithIssuerURL(issuerURL))
	require.NoError(t, err)

	_, gotProvider, err := ResolveKeyFunc("https://different-issuer.example", time.Minute, provider)
	require.NoError(t, err)
	assert.Same(t, provider, gotProvider)
}

func TestResolveKeyFunc_WrapsInvalidIssuerURLError(t *testing.T) {
	_, _, err := ResolveKeyFunc("https://issuer.example/\x7f", time.Minute, nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid issuer URL")

	inner := errors.Unwrap(err)
	require.NotNil(t, inner, "the underlying url.Parse error must be unwrappable, not just interpolated")
}

// TestValidatedClaimsToMapClaims_PopulatesRegisteredClaims pins the exact
// map produced from a fully-populated RegisteredClaims and from an
// all-zero-value one. Each registered field is guarded by its own
// if-non-zero check before being added to the map; asserting on the exact
// key set (not just individual field presence) catches a guard that was
// silently dropped or a comparison that was weakened.
func TestValidatedClaimsToMapClaims_PopulatesRegisteredClaims(t *testing.T) {
	t.Run("fully populated", func(t *testing.T) {
		vc := &jwtvalidator.ValidatedClaims{
			RegisteredClaims: jwtvalidator.RegisteredClaims{
				Issuer:    "https://issuer.example",
				Subject:   "test-user",
				Audience:  []string{"aud1", "aud2"},
				Expiry:    1700000100,
				NotBefore: 1700000000,
				IssuedAt:  1700000050,
				ID:        "jti-123",
			},
		}

		m, err := validatedClaimsToMapClaims(vc)
		require.NoError(t, err)
		assert.Equal(t, jwt.MapClaims{
			"iss": "https://issuer.example",
			"sub": "test-user",
			"aud": []string{"aud1", "aud2"},
			"exp": int64(1700000100),
			"nbf": int64(1700000000),
			"iat": int64(1700000050),
			"jti": "jti-123",
		}, m)
	})

	t.Run("zero value", func(t *testing.T) {
		vc := &jwtvalidator.ValidatedClaims{}

		m, err := validatedClaimsToMapClaims(vc)
		require.NoError(t, err)
		assert.Equal(t, jwt.MapClaims{}, m)
	})

	t.Run("single audience", func(t *testing.T) {
		// A single-element Audience distinguishes len(rc.Audience) > 0 from a
		// boundary off-by-one (> 1): the multi-element "fully populated" case
		// above satisfies both, so it can't catch that mutation alone.
		vc := &jwtvalidator.ValidatedClaims{
			RegisteredClaims: jwtvalidator.RegisteredClaims{Audience: []string{"aud1"}},
		}

		m, err := validatedClaimsToMapClaims(vc)
		require.NoError(t, err)
		assert.Equal(t, jwt.MapClaims{"aud": []string{"aud1"}}, m)
	})

	t.Run("merges custom claims", func(t *testing.T) {
		vc := &jwtvalidator.ValidatedClaims{
			RegisteredClaims: jwtvalidator.RegisteredClaims{Subject: "test-user"},
			CustomClaims:     &testCustomClaims{Role: "admin"},
		}

		m, err := validatedClaimsToMapClaims(vc)
		require.NoError(t, err)
		assert.Equal(t, jwt.MapClaims{
			"sub":  "test-user",
			"role": "admin",
		}, m)
	})
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

package oidc_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/oidc"
)

// TestHMACValidatorAcceptsAnyIssuer verifies that HMAC mode accepts tokens
// with any issuer claim, enabling flexible local smoke testing.
func TestHMACValidatorAcceptsAnyIssuer(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret: "test-secret",
		Audiences:  []string{"test"}, // Required by validator
		// Issuer omitted to test synthetic issuer path
	}

	v, err := oidc.NewValidatorFromConfig(cfg)
	require.NoError(t, err, "should create validator with HMAC secret and no issuer")

	// Create a token with a custom issuer claim
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": "custom-issuer", // Custom issuer should be accepted
		"aud": "test",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err, "should sign token")

	// Validate should succeed even though iss != "local-smoke"
	_, err = v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err, "HMAC validator should accept token with custom issuer")
}

// TestHMACValidatorRejectsEmptyIssuer verifies that tokens without an
// iss claim are rejected (validator library requirement).
func TestHMACValidatorRejectsEmptyIssuer(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret: "test-secret",
		Audiences:  []string{"test"}, // Required by validator
	}

	v, err := oidc.NewValidatorFromConfig(cfg)
	require.NoError(t, err, "should create validator")

	// Create a token WITHOUT an issuer claim
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		// "iss" omitted intentionally
		"aud": "test",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err, "should sign token")

	// Validate should fail because no iss claim present
	_, err = v.ValidateToken(context.Background(), tokenString)
	require.Error(t, err, "validator should reject token without iss claim")
}

// TestNormalValidatorEnforcesIssuer verifies that in non-HMAC mode,
// the configured issuer is enforced (mismatched issuer claims are rejected).
func TestNormalValidatorEnforcesIssuer(t *testing.T) {
	// Use a deterministic keyFunc to test issuer enforcement directly
	keyFunc := func(ctx context.Context) (any, error) {
		return []byte("test-secret"), nil
	}

	cfg := &oidc.ValidatorConfig{
		Issuer:             "https://example.com",
		SignatureAlgorithm: "HS256", // Use HMAC for deterministic testing
		Audiences:          []string{"test"},
	}

	v, err := oidc.NewValidatorFromConfigWithOptions(
		cfg,
		oidc.WithValidatorKeyFunc(keyFunc),
	)
	require.NoError(t, err, "should create validator with deterministic keyFunc")

	// Token with matching issuer should pass
	now := time.Now()
	matchToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://example.com",
		"aud": "test",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	})
	matchTokenString, err := matchToken.SignedString([]byte("test-secret"))
	require.NoError(t, err, "should sign matching token")

	_, err = v.ValidateToken(context.Background(), matchTokenString)
	require.NoError(t, err, "validator should accept token with matching issuer")

	// Token with mismatched issuer should fail
	mismatchToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://wrong-issuer.com",
		"aud": "test",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	})
	mismatchTokenString, err := mismatchToken.SignedString([]byte("test-secret"))
	require.NoError(t, err, "should sign mismatched token")

	_, err = v.ValidateToken(context.Background(), mismatchTokenString)
	require.Error(t, err, "validator should reject token with mismatched issuer")
}

// TestHMACValidatorEnforcesHS256Algorithm verifies that when HMACSecret is set,
// the algorithm is enforced to be a symmetric HMAC variant even if a different
// algorithm is configured.
func TestHMACValidatorEnforcesHS256Algorithm(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret:         "test-secret",
		SignatureAlgorithm: "RS256", // Asymmetric algorithm incompatible with HMAC
		Audiences:          []string{"test"},
	}

	v, err := oidc.NewValidatorFromConfig(cfg)
	require.NoError(t, err, "should create validator, overriding algorithm to HS256")

	// Create a token signed with HS256 (what the validator should expect)
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": "test-issuer",
		"aud": "test",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err, "should sign token with HS256")

	// Validation should succeed because validator was corrected to use HS256
	_, err = v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err, "HMAC validator should succeed with corrected HS256 algorithm")
}

// TestHMACValidatorWithCustomKeyFuncAndNoIssuer verifies that when HMACSecret is set
// along with a custom keyFunc, the synthetic issuer is still established for HMAC mode.
func TestHMACValidatorWithCustomKeyFuncAndNoIssuer(t *testing.T) {
	customKeyFunc := func(ctx context.Context) (any, error) {
		return []byte("test-secret"), nil
	}

	cfg := &oidc.ValidatorConfig{
		HMACSecret: "test-secret", // Indicates HMAC mode
		Audiences:  []string{"test"},
		// Issuer omitted, and custom keyFunc provided
	}

	v, err := oidc.NewValidatorFromConfigWithOptions(
		cfg,
		oidc.WithValidatorKeyFunc(customKeyFunc),
	)
	require.NoError(t, err, "should create validator with HMACSecret + custom keyFunc + no issuer")

	// Create a token with a custom issuer
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": "custom-issuer",
		"aud": "test",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err, "should sign token")

	// Validation should succeed because synthetic issuer and HMAC mode should be set up
	_, err = v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err, "HMAC validator with custom keyFunc should accept token with any issuer")
}

// TestNormalValidatorRequiresAudiences verifies that in non-HMAC mode, omitting
// audiences causes validator creation to fail. NewValidatorFromConfigWithOptions
// enforces this as an explicit guard before constructing the underlying validator,
// preventing accidental deployments without audience checking.
func TestNormalValidatorRequiresAudiences(t *testing.T) {
	keyFunc := func(ctx context.Context) (any, error) {
		return []byte("test-secret"), nil
	}

	cfg := &oidc.ValidatorConfig{
		Issuer:             "https://example.com",
		SignatureAlgorithm: "HS256",
		// Audiences intentionally omitted: validator creation must fail
	}

	_, err := oidc.NewValidatorFromConfigWithOptions(cfg, oidc.WithValidatorKeyFunc(keyFunc))
	require.Error(t, err, "should fail to create validator when no audiences are configured in normal mode")
}

// TestHMACValidatorWithNoAudiencesUsesLocalSmokeDefault verifies that in HMAC
// smoke-test mode without explicit audiences, the default "local-smoke" audience
// is enforced. Tokens carrying that audience are accepted; others are rejected.
func TestHMACValidatorWithNoAudiencesUsesLocalSmokeDefault(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret: "test-secret",
		// Audiences intentionally omitted to test the "local-smoke" default path
	}

	v, err := oidc.NewValidatorFromConfig(cfg)
	require.NoError(t, err, "should create HMAC validator with no audiences")

	now := time.Now()

	// Token with the default "local-smoke" audience should be accepted
	smokeToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": "local-smoke",
		"aud": "local-smoke",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	})
	smokeTokenStr, err := smokeToken.SignedString([]byte("test-secret"))
	require.NoError(t, err)
	_, err = v.ValidateToken(context.Background(), smokeTokenStr)
	require.NoError(t, err, "HMAC validator with no audiences should accept token with 'local-smoke' aud")

	// Token with a different audience should be rejected
	otherAudToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": "local-smoke",
		"aud": "other-audience",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	})
	otherAudStr, err := otherAudToken.SignedString([]byte("test-secret"))
	require.NoError(t, err)
	_, err = v.ValidateToken(context.Background(), otherAudStr)
	require.Error(t, err, "HMAC validator with no audiences should reject token with non-'local-smoke' aud")
}

// TestHMACValidatorEnforcesExplicitIssuer verifies that when HMACSecret is set
// along with an explicit issuer, the issuer is still enforced (not bypassed).
func TestHMACValidatorEnforcesExplicitIssuer(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret: "test-secret",
		Issuer:     "https://example.com", // Explicit issuer
		Audiences:  []string{"test"},
	}

	v, err := oidc.NewValidatorFromConfig(cfg)
	require.NoError(t, err, "should create validator with HMACSecret and explicit issuer")

	// Create a token with the correct issuer
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://example.com",
		"aud": "test",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err, "should sign token")

	// Validation should succeed with matching issuer
	_, err = v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err, "validator should accept token with matching issuer")

	// Create a token with a wrong issuer
	wrongToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://wrong-issuer.com",
		"aud": "test",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	})

	wrongTokenString, err := wrongToken.SignedString([]byte("test-secret"))
	require.NoError(t, err, "should sign token")

	// Validation should fail with wrong issuer
	_, err = v.ValidateToken(context.Background(), wrongTokenString)
	require.Error(t, err, "validator should reject token with wrong issuer, even in HMAC mode")
}

package oidc_test

import (
	"context"
	"errors"
	"testing"
	"time"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/oidc"
)

// TestHMACValidatorAcceptsAnyIssuer verifies that HMAC mode accepts tokens
// with any issuer claim, enabling flexible local smoke testing.
func TestHMACValidatorAcceptsAnyIssuer(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret:        "test-secret",
		AllowInsecureHMAC: true,
		Audiences:         []string{"test"}, // Required by validator
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
		HMACSecret:        "test-secret",
		AllowInsecureHMAC: true,
		Audiences:         []string{"test"}, // Required by validator
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
		AllowInsecureHMAC:  true,
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

func TestHMACValidatorFiltersNonHMACAlgorithmsFromList(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret:          "test-secret",
		AllowInsecureHMAC:   true,
		SignatureAlgorithms: []string{"RS256", "HS256"},
		Audiences:           []string{"test"},
	}

	v, err := oidc.NewValidatorFromConfig(cfg)
	require.NoError(t, err, "should create validator with mixed algorithms by filtering to HMAC")

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

	_, err = v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err, "validator should accept HS256 token after filtering non-HMAC algorithms")
}

// TestValidatorDefaultsAllowedClockSkewToOneMinute is the regression test for
// the drift fixed by consolidating onto jwt.ResolveAllowedClockSkew: an
// unconfigured AllowedClockSkew previously meant zero tolerance in oidc
// (unlike jwt's one-minute default), so a token already expired by 30
// seconds would be rejected. It must now be accepted.
func TestValidatorDefaultsAllowedClockSkewToOneMinute(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret:        "test-secret",
		AllowInsecureHMAC: true,
		Issuer:            "test-issuer",
		Audiences:         []string{"test"},
	}

	v, err := oidc.NewValidatorFromConfig(cfg)
	require.NoError(t, err)

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": "test-issuer",
		"aud": "test",
		"iat": now.Add(-2 * time.Hour).Unix(),
		"exp": now.Add(-30 * time.Second).Unix(), // expired 30s ago
	})

	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	_, err = v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err, "a token expired 30s ago must validate within the default one-minute clock skew")
}

func TestValidatorRejectsInvalidSignatureAlgorithms(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		Issuer:              "https://example.com",
		SignatureAlgorithms: []string{"RS256", "NOT_REAL"},
		Audiences:           []string{"test"},
	}

	_, err := oidc.NewValidatorFromConfigWithOptions(cfg, oidc.WithValidatorKeyFunc(func(context.Context) (any, error) {
		return []byte("test-secret"), nil
	}))
	require.Error(t, err)
}

// TestHMACValidatorWithCustomKeyFuncAndNoIssuer verifies that when HMACSecret is set
// along with a custom keyFunc, the synthetic issuer is still established for HMAC mode.
func TestHMACValidatorWithCustomKeyFuncAndNoIssuer(t *testing.T) {
	customKeyFunc := func(ctx context.Context) (any, error) {
		return []byte("test-secret"), nil
	}

	cfg := &oidc.ValidatorConfig{
		HMACSecret:        "test-secret", // Indicates HMAC mode
		AllowInsecureHMAC: true,
		Audiences:         []string{"test"},
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
		HMACSecret:        "test-secret",
		AllowInsecureHMAC: true,
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
		HMACSecret:        "test-secret",
		AllowInsecureHMAC: true,
		Issuer:            "https://example.com", // Explicit issuer
		Audiences:         []string{"test"},
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

// TestHMACValidatorSwallowsIntrospectionParseFailure is the regression test
// for enrichingValidator's graceful-degradation contract: a token with a
// custom claim shape json.Unmarshal can't coerce into IntrospectionResponse
// (here, "email_verified" as a string instead of a bool -- a type the
// underlying jwt-middleware validator itself never inspects, so the token
// still validates) must not fail overall validation, and CustomClaims must
// stay nil rather than being set to a partially-populated struct.
func TestHMACValidatorSwallowsIntrospectionParseFailure(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret:        "test-secret",
		AllowInsecureHMAC: true,
		Audiences:         []string{"test"},
	}

	v, err := oidc.NewValidatorFromConfig(cfg)
	require.NoError(t, err)

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":            "test-user",
		"iss":            "custom-issuer",
		"aud":            "test",
		"iat":            now.Unix(),
		"exp":            now.Add(1 * time.Hour).Unix(),
		"email_verified": "not-a-bool",
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	out, err := v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err, "an unparsable custom-claims shape must not fail overall token validation")

	vc, ok := out.(*jwtvalidator.ValidatedClaims)
	require.True(t, ok)
	assert.Nil(t, vc.CustomClaims, "CustomClaims must stay nil, not a partially-populated struct, when introspection parsing fails")
}

func TestHMACValidatorPopulatesIntrospectionCustomClaims(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret:        "test-secret",
		AllowInsecureHMAC: true,
		Audiences:         []string{"test"},
	}

	v, err := oidc.NewValidatorFromConfig(cfg)
	require.NoError(t, err, "should create validator with HMAC secret")

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": "custom-issuer",
		"aud": []string{"test"},
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
		"realm_access": map[string]any{
			"roles": []string{"connect-admin", "registry.publisher"},
		},
	})

	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err, "should sign token")

	out, err := v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err, "HMAC validator should validate token")

	vc, ok := out.(*jwtvalidator.ValidatedClaims)
	require.True(t, ok, "validator should return *ValidatedClaims")

	custom, ok := vc.CustomClaims.(*oidc.IntrospectionResponse)
	require.True(t, ok, "custom claims should be IntrospectionResponse")
	require.Equal(t, "test-user", custom.Subject)
	require.Equal(t, "test", custom.Audience)
	require.Equal(t, []string{"connect-admin", "registry.publisher"}, custom.RealmAccess.Roles)
	require.Equal(t, "Bearer", custom.TokenType)
}

// TestNewValidatorFromConfigWithOptions_ExplicitIssuerTakesPrecedenceOverURL
// is the regression test for issuer pinning: when both Issuer and the
// endpoint URL are configured with different values, the explicit Issuer
// must win. A validator that silently fell back to the URL whenever both
// were set would let a separately-supplied URL field override a pinned
// issuer -- weakening issuer enforcement.
func TestNewValidatorFromConfigWithOptions_ExplicitIssuerTakesPrecedenceOverURL(t *testing.T) {
	const explicitIssuer = "https://explicit-issuer.example"
	const fallbackURL = "https://fallback-url.example"

	cfg := &oidc.ValidatorConfig{
		EndpointConfig:     oidc.EndpointConfig{URL: fallbackURL},
		Issuer:             explicitIssuer,
		SignatureAlgorithm: "HS256",
		Audiences:          []string{"test"},
	}

	v, err := oidc.NewValidatorFromConfigWithOptions(
		cfg,
		oidc.WithValidatorKeyFunc(func(context.Context) (any, error) {
			return []byte("test-secret"), nil
		}),
	)
	require.NoError(t, err)

	now := time.Now()
	newToken := func(issuer string) string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "test-user",
			"iss": issuer,
			"aud": "test",
			"iat": now.Unix(),
			"exp": now.Add(time.Hour).Unix(),
		})
		s, signErr := token.SignedString([]byte("test-secret"))
		require.NoError(t, signErr)
		return s
	}

	_, err = v.ValidateToken(context.Background(), newToken(explicitIssuer))
	assert.NoError(t, err, "validator must accept the explicitly configured issuer")

	_, err = v.ValidateToken(context.Background(), newToken(fallbackURL))
	assert.Error(t, err, "validator must not accept the URL as issuer when Issuer is explicitly set")
}

// TestNewValidatorFromConfigWithOptions_FallsBackToURLWhenIssuerEmpty
// verifies the intended use of the URL-as-issuer fallback: when Issuer is
// unset, the validator must use the configured URL as the issuer.
func TestNewValidatorFromConfigWithOptions_FallsBackToURLWhenIssuerEmpty(t *testing.T) {
	const fallbackURL = "https://fallback-url.example"

	cfg := &oidc.ValidatorConfig{
		EndpointConfig:     oidc.EndpointConfig{URL: fallbackURL},
		SignatureAlgorithm: "HS256",
		Audiences:          []string{"test"},
	}

	v, err := oidc.NewValidatorFromConfigWithOptions(
		cfg,
		oidc.WithValidatorKeyFunc(func(context.Context) (any, error) {
			return []byte("test-secret"), nil
		}),
	)
	require.NoError(t, err)

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": fallbackURL,
		"aud": "test",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	_, err = v.ValidateToken(context.Background(), tokenString)
	assert.NoError(t, err, "validator should accept the URL as the issuer when Issuer is unset")
}

// TestNewValidatorFromConfigWithOptions_RequiresIssuerOrURL pins the error
// returned when neither Issuer nor URL is configured.
func TestNewValidatorFromConfigWithOptions_RequiresIssuerOrURL(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		SignatureAlgorithm: "HS256",
		Audiences:          []string{"test"},
	}

	_, err := oidc.NewValidatorFromConfigWithOptions(cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "issuer or URL must be provided")
}

// TestNewValidatorFromConfigWithOptions_WrapsSignatureAlgorithmResolutionError
// verifies both that an invalid signature-algorithm entry is rejected, and
// that the error is wrapped (not just stringified) so callers can unwrap it.
func TestNewValidatorFromConfigWithOptions_WrapsSignatureAlgorithmResolutionError(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		Issuer:              "https://issuer.example",
		SignatureAlgorithms: []string{""},
		Audiences:           []string{"test"},
	}

	_, err := oidc.NewValidatorFromConfigWithOptions(cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "resolving signature algorithms")

	inner := errors.Unwrap(err)
	require.NotNil(t, inner, "the underlying signature-algorithm error must be unwrappable, not just interpolated into the message")
	assert.ErrorContains(t, inner, "signature_algorithms[0] must not be empty")
}

// TestNewValidatorFromConfigWithOptions_RejectsHMACSecretWithoutAllowInsecureHMAC
// is the regression test for accidental production use of a static HMAC
// shared secret: HMACSecret must be rejected unless AllowInsecureHMAC is
// explicitly set to true.
func TestNewValidatorFromConfigWithOptions_RejectsHMACSecretWithoutAllowInsecureHMAC(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret: "test-secret",
		Audiences:  []string{"test"},
		// AllowInsecureHMAC intentionally omitted (defaults to false).
	}

	_, err := oidc.NewValidatorFromConfigWithOptions(cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "AllowInsecureHMAC")
}

// TestNewValidatorFromConfigWithOptions_RequiresAudiencesInNonHMACMode is the
// regression test for the "critical security check" documented on
// buildValidatorOptions: non-HMAC (production) mode must reject a config
// with no configured audiences rather than silently constructing a
// validator that accepts tokens for any audience.
func TestNewValidatorFromConfigWithOptions_RequiresAudiencesInNonHMACMode(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		Issuer:             "https://issuer.example",
		SignatureAlgorithm: "HS256",
		// Audiences intentionally omitted; HMACSecret intentionally unset so
		// the HMAC smoke-test default audience doesn't apply.
	}

	_, err := oidc.NewValidatorFromConfigWithOptions(
		cfg,
		oidc.WithValidatorKeyFunc(func(context.Context) (any, error) {
			return []byte("test-secret"), nil
		}),
	)
	require.Error(t, err)
	assert.ErrorContains(t, err, "audiences must be configured in non-HMAC mode")
}

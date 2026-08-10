package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/rs/zerolog"

	"github.com/dioad/auth/jwt"
	"github.com/dioad/auth/oidc/aws"
	"github.com/dioad/auth/oidc/flyio"
	"github.com/dioad/auth/oidc/githubactions"
)

// isHMACAlgorithm checks if the given SignatureAlgorithm is a symmetric HMAC variant.
func isHMACAlgorithm(alg validator.SignatureAlgorithm) bool {
	return strings.HasPrefix(string(alg), "HS")
}

// TokenValidator is an alias for jwt.TokenValidator.
type TokenValidator = jwt.TokenValidator

// ValidatorOpt configures validator creation.
type ValidatorOpt func(*validatorOptions)

type validatorOptions struct {
	keyFunc             func(context.Context) (any, error)
	jwksProvider        *jwks.CachingProvider
	customClaimsFactory func() validator.CustomClaims
}

// WithValidatorKeyFunc sets a custom key function for validation.
func WithValidatorKeyFunc(keyFunc func(context.Context) (any, error)) ValidatorOpt {
	return func(o *validatorOptions) {
		if keyFunc != nil {
			o.keyFunc = keyFunc
		}
	}
}

// WithValidatorCustomClaimsFactory sets a custom claims factory for the validator.
// When set, the validator will deserialize JWT payloads into the type returned by
// the factory, enabling provider-specific PrincipalSource implementations to
// extract typed claims from the context.
func WithValidatorCustomClaimsFactory(factory func() validator.CustomClaims) ValidatorOpt {
	return func(o *validatorOptions) {
		if factory != nil {
			o.customClaimsFactory = factory
		}
	}
}

// WithValidatorJWKSProvider sets a custom JWKS caching provider.
func WithValidatorJWKSProvider(provider *jwks.CachingProvider) ValidatorOpt {
	return func(o *validatorOptions) {
		if provider != nil {
			o.jwksProvider = provider
		}
	}
}

// NewValidatorFromConfig creates a TokenValidator from a ValidatorConfig.
func NewValidatorFromConfig(cfg *ValidatorConfig) (jwt.TokenValidator, error) {
	return NewValidatorFromConfigWithOptions(cfg)
}

// NewValidatorFromConfigWithOptions creates a TokenValidator from a ValidatorConfig using custom options.
func NewValidatorFromConfigWithOptions(cfg *ValidatorConfig, opts ...ValidatorOpt) (jwt.TokenValidator, error) {
	// Use a local issuer variable to avoid mutating the caller's config
	issuer := cfg.Issuer
	if issuer == "" && cfg.URL != "" {
		// For now, use the URL as issuer if not provided
		issuer = cfg.URL
	}

	algorithms, err := jwt.ResolveSignatureAlgorithms(
		cfg.SignatureAlgorithm,
		cfg.SignatureAlgorithms,
		jwt.DefaultSignatureAlgorithms(),
	)
	if err != nil {
		return nil, fmt.Errorf("resolving signature algorithms: %w", err)
	}

	options := &validatorOptions{}
	for _, opt := range opts {
		opt(options)
	}

	issuer, algorithms, hmacFlexibleIssuer, err := applyHMACOverrides(cfg, issuer, algorithms, options)
	if err != nil {
		return nil, err
	}
	if issuer == "" {
		return nil, fmt.Errorf("issuer or URL must be provided")
	}

	if options.keyFunc == nil {
		keyFunc, provider, err := jwt.ResolveKeyFunc(issuer, time.Duration(cfg.CacheTTL)*time.Second, options.jwksProvider)
		if err != nil {
			return nil, err
		}
		options.keyFunc = keyFunc
		options.jwksProvider = provider
	}

	// Resolve the custom claims factory: explicit option takes precedence,
	// then auto-detect from the config Type field.
	if options.customClaimsFactory == nil {
		options.customClaimsFactory = customClaimsFactoryForType(cfg.Type)
	}

	validatorOpts, err := buildValidatorOptions(cfg, issuer, algorithms, hmacFlexibleIssuer, options)
	if err != nil {
		return nil, err
	}

	v, err := validator.New(validatorOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}

	tv := jwt.NewAuth0Validator(v, issuer)
	if cfg.HMACSecret != "" {
		// HMAC smoke-test tokens are validated with the generic claims map, not
		// a provider-specific typed CustomClaims factory, so attempt to
		// populate CustomClaims by re-parsing the token payload.
		tv = &enrichingValidator{TokenValidator: tv}
	}

	return jwt.WrapValidator(tv, cfg.ClaimPredicate, cfg.Debug), nil
}

// applyHMACOverrides adjusts algorithms/keyFunc/issuer for HMAC shared-secret
// smoke-test mode: algorithms are restricted to HS*, the key function returns
// the static secret directly (skipping JWKS discovery), and — when no issuer
// was configured — issuer validation becomes flexible (any issuer claim is
// accepted) since smoke tokens may carry an arbitrary iss value. Mutates
// options.keyFunc in place when HMAC mode applies and no custom keyFunc was
// already provided. Returns issuer/algorithms unchanged when cfg.HMACSecret
// is empty.
func applyHMACOverrides(cfg *ValidatorConfig, issuer string, algorithms []validator.SignatureAlgorithm, options *validatorOptions) (string, []validator.SignatureAlgorithm, bool, error) {
	if cfg.HMACSecret == "" {
		return issuer, algorithms, false, nil
	}
	if !cfg.AllowInsecureHMAC {
		return "", nil, false, fmt.Errorf("HMACSecret requires AllowInsecureHMAC: true — HMAC shared secrets are not suitable for production")
	}

	if options.keyFunc == nil {
		secret := []byte(cfg.HMACSecret)
		options.keyFunc = func(_ context.Context) (any, error) { return secret, nil }
	}

	// HMAC requires a symmetric signing algorithm (HS256/HS384/HS512).
	// Override any non-HS algorithm to prevent runtime failures.
	hmacAlgorithms := make([]validator.SignatureAlgorithm, 0, len(algorithms))
	for _, algorithm := range algorithms {
		if isHMACAlgorithm(algorithm) {
			hmacAlgorithms = append(hmacAlgorithms, algorithm)
		}
	}
	if len(hmacAlgorithms) == 0 {
		hmacAlgorithms = []validator.SignatureAlgorithm{validator.HS256}
	}

	// For HMAC smoke tests without an explicit issuer, accept any issuer
	// claim. If an issuer was explicitly configured, enforce it.
	flexibleIssuer := false
	if issuer == "" {
		issuer = "local-smoke"
		flexibleIssuer = true
	}

	return issuer, hmacAlgorithms, flexibleIssuer, nil
}

// buildValidatorOptions assembles the auth0 validator.Option list for cfg,
// given the already-resolved issuer/algorithms/HMAC-flexible-issuer state and
// key/custom-claims options.
func buildValidatorOptions(cfg *ValidatorConfig, issuer string, algorithms []validator.SignatureAlgorithm, hmacFlexibleIssuer bool, options *validatorOptions) ([]validator.Option, error) {
	validatorOpts := []validator.Option{
		validator.WithKeyFunc(options.keyFunc),
		validator.WithAllowedClockSkew(jwt.ResolveAllowedClockSkew(cfg.AllowedClockSkew)),
	}
	if len(algorithms) == 1 {
		validatorOpts = append(validatorOpts, validator.WithAlgorithm(algorithms[0]))
	} else {
		validatorOpts = append(validatorOpts, validator.WithAlgorithms(algorithms))
	}
	if options.customClaimsFactory != nil {
		validatorOpts = append(validatorOpts, validator.WithCustomClaims(options.customClaimsFactory))
	}

	switch {
	case len(cfg.Audiences) > 0:
		validatorOpts = append(validatorOpts, validator.WithAudiences(cfg.Audiences))
	case cfg.HMACSecret != "":
		// HMAC smoke-test mode with no explicit audiences: accept the default smoke audience.
		// Tokens generated by gen_smoke_token.py include aud: "local-smoke" by default.
		validatorOpts = append(validatorOpts, validator.WithAudience("local-smoke"))
	default:
		// Non-HMAC mode (production) requires explicit audience configuration to prevent
		// accidental deployments without audience validation, which is a critical security check.
		return nil, fmt.Errorf("audiences must be configured in non-HMAC mode")
	}

	if cfg.HMACSecret != "" && hmacFlexibleIssuer {
		// HMAC mode with no explicit issuer: accept any issuer claim by returning the token's issuer.
		// This enables flexible local smoke testing where tokens can have any iss value.
		validatorOpts = append(validatorOpts, validator.WithIssuersResolver(anyIssuerResolver))
	} else {
		// Normal mode or HMAC with explicit issuer: enforce the configured issuer
		validatorOpts = append(validatorOpts, validator.WithIssuer(issuer))
	}

	return validatorOpts, nil
}

// anyIssuerResolver accepts any issuer claim by echoing the token's own iss
// value back. Used for HMAC smoke-test mode with no explicit issuer
// configured; the validator library requires an iss claim to be present, so
// an absent issuer still fails validation.
func anyIssuerResolver(ctx context.Context) ([]string, error) {
	if iss, ok := validator.IssuerFromContext(ctx); ok && iss != "" {
		return []string{iss}, nil
	}
	return []string{}, nil
}

// customClaimsFactoryForType returns a custom claims factory for the given
// provider type. Returns nil for unknown types, which causes the validator
// to use the default generic claims map.
func customClaimsFactoryForType(providerType string) func() validator.CustomClaims {
	switch providerType {
	case "flyio":
		return func() validator.CustomClaims { return &flyio.Claims{} }
	case "aws":
		return func() validator.CustomClaims { return &aws.Claims{} }
	case "githubactions":
		return func() validator.CustomClaims { return &githubactions.Claims{} }
	default:
		return nil
	}
}

// enrichingValidator wraps a TokenValidator built without a typed CustomClaims
// factory (the HMAC smoke-test path) and attempts to populate CustomClaims by
// re-parsing the token payload as an IntrospectionResponse after validation
// succeeds. String() and all other behavior delegate to the embedded
// TokenValidator.
type enrichingValidator struct {
	jwt.TokenValidator
}

func (v *enrichingValidator) ValidateToken(ctx context.Context, tokenString string) (any, error) {
	claims, err := v.TokenValidator.ValidateToken(ctx, tokenString)
	if err != nil {
		return claims, err
	}

	vc, ok := claims.(*validator.ValidatedClaims)
	if !ok || vc.CustomClaims != nil {
		return claims, nil
	}

	customClaimsMap, err := jwt.ClaimsMapFromToken(tokenString)
	if err != nil {
		return claims, nil
	}

	customClaims, err := introspectionFromClaimsMap(customClaimsMap)
	if err != nil {
		return claims, nil
	}
	if customClaims.TokenType == "" {
		customClaims.TokenType = "Bearer"
	}
	if customClaims.Audience == "" && len(vc.RegisteredClaims.Audience) > 0 {
		customClaims.Audience = vc.RegisteredClaims.Audience[0]
	}

	vc.CustomClaims = &customClaims
	return claims, nil
}

func introspectionFromClaimsMap(rawClaims map[string]any) (IntrospectionResponse, error) {
	var customClaims IntrospectionResponse

	payload, err := json.Marshal(rawClaims)
	if err != nil {
		return customClaims, err
	}
	if err := json.Unmarshal(payload, &customClaims); err == nil {
		return customClaims, nil
	}

	// Some tokens emit "aud" as an array while IntrospectionResponse expects a
	// string; tolerate that mismatch for compatibility when populating typed claims.
	sanitized := maps.Clone(rawClaims)
	delete(sanitized, "aud")
	payload, err = json.Marshal(sanitized)
	if err != nil {
		return customClaims, err
	}
	if err := json.Unmarshal(payload, &customClaims); err != nil {
		return customClaims, err
	}
	return customClaims, nil
}

type validatorDebugger struct {
	jwt.TokenValidator
	logger zerolog.Logger
}

func (v *validatorDebugger) ValidateToken(ctx context.Context, tokenString string) (any, error) {
	claims, err := v.TokenValidator.ValidateToken(ctx, tokenString)
	if err != nil {
		v.logger.Error().Err(err).Msg("Token validation failed")
	} else {
		v.logger.Debug().Msg("Token validation succeeded")
	}
	return claims, err
}

func (v *validatorDebugger) String() string {
	return fmt.Sprintf("ValidatorDebugger(%s)", v.TokenValidator.String())
}

// DebuggerOpt configures a TokenValidator debugger.
type DebuggerOpt func(*validatorDebugger)

// WithLogger sets the logger for validator debug output.
func WithLogger(logger zerolog.Logger) DebuggerOpt {
	return func(v *validatorDebugger) {
		v.logger = logger
	}
}

// NewValidatorDebugger wraps a TokenValidator with debugging output.
func NewValidatorDebugger(v jwt.TokenValidator, opts ...DebuggerOpt) jwt.TokenValidator {
	dv := &validatorDebugger{TokenValidator: v, logger: zerolog.Nop()}
	for _, opt := range opts {
		opt(dv)
	}
	return dv
}

// NewMultiValidatorFromConfig creates a MultiValidator from multiple configs.
func NewMultiValidatorFromConfig(configs []ValidatorConfig, opts ...validator.Option) (jwt.TokenValidator, error) {
	var validators []jwt.TokenValidator
	for _, cfg := range configs {
		v, err := NewValidatorFromConfig(&cfg)
		if err != nil {
			return nil, err
		}
		validators = append(validators, v)
	}
	return &jwt.MultiValidator{Validators: validators}, nil
}

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
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

	// Track whether HMAC mode should use flexible issuer validation
	hmacFlexibleIssuer := false

	// Static HMAC secret short-circuits JWKS discovery. Intended for local
	// development / smoke tests only.
	if cfg.HMACSecret != "" {
		secret := []byte(cfg.HMACSecret)
		// Only override keyFunc if no custom keyFunc was provided via options
		if options.keyFunc == nil {
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
		algorithms = hmacAlgorithms
		// For HMAC smoke tests without an explicit issuer, accept any issuer claim.
		// If an issuer was explicitly configured, enforce it.
		if issuer == "" {
			// No issuer preference; set a dummy issuer for the validator library
			// (which requires at least one to be set), then use flexible validation.
			issuer = "local-smoke"
			hmacFlexibleIssuer = true
		}
	}

	if issuer == "" {
		return nil, fmt.Errorf("issuer or URL must be provided")
	}

	if options.keyFunc == nil {
		issuerURL, err := url.Parse(issuer)
		if err != nil {
			return nil, fmt.Errorf("invalid issuer URL: %w", err)
		}
		cacheTTL := time.Duration(cfg.CacheTTL) * time.Second
		if cacheTTL <= 0 {
			cacheTTL = 5 * time.Minute
		}
		if options.jwksProvider == nil {
			var err error
			options.jwksProvider, err = jwks.NewCachingProvider(
				jwks.WithIssuerURL(issuerURL),
				jwks.WithCacheTTL(cacheTTL),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create JWKS caching provider: %w", err)
			}
		}
		options.keyFunc = options.jwksProvider.KeyFunc
	}
	if options.keyFunc == nil {
		return nil, fmt.Errorf("key function not configured")
	}

	// Resolve the custom claims factory: explicit option takes precedence,
	// then auto-detect from the config Type field.
	if options.customClaimsFactory == nil {
		options.customClaimsFactory = customClaimsFactoryForType(cfg.Type)
	}

	// Build validator options.
	validatorOpts := []validator.Option{
		validator.WithKeyFunc(options.keyFunc),
		validator.WithAllowedClockSkew(time.Duration(cfg.AllowedClockSkew) * time.Second),
	}
	if len(algorithms) == 1 {
		validatorOpts = append(validatorOpts, validator.WithAlgorithm(algorithms[0]))
	} else {
		validatorOpts = append(validatorOpts, validator.WithAlgorithms(algorithms))
	}
	if options.customClaimsFactory != nil {
		validatorOpts = append(validatorOpts, validator.WithCustomClaims(options.customClaimsFactory))
	}
	if len(cfg.Audiences) > 0 {
		validatorOpts = append(validatorOpts, validator.WithAudiences(cfg.Audiences))
	} else if cfg.HMACSecret != "" {
		// HMAC smoke-test mode with no explicit audiences: accept the default smoke audience.
		// Tokens generated by gen_smoke_token.py include aud: "local-smoke" by default.
		validatorOpts = append(validatorOpts, validator.WithAudience("local-smoke"))
	} else {
		// Non-HMAC mode (production) requires explicit audience configuration to prevent
		// accidental deployments without audience validation, which is a critical security check.
		return nil, fmt.Errorf("audiences must be configured in non-HMAC mode")
	}

	if cfg.HMACSecret != "" && hmacFlexibleIssuer {
		// HMAC mode with no explicit issuer: accept any issuer claim by returning the token's issuer.
		// This enables flexible local smoke testing where tokens can have any iss value.
		validatorOpts = append(validatorOpts,
			validator.WithIssuersResolver(func(ctx context.Context) ([]string, error) {
				// Extract the issuer from the token (already in context by the validator)
				if iss, ok := validator.IssuerFromContext(ctx); ok && iss != "" {
					return []string{iss}, nil
				}
				// No issuer in token; return empty list which will cause validation to fail
				// (validator library requires iss claim to be present)
				return []string{}, nil
			}),
		)
	} else {
		// Normal mode or HMAC with explicit issuer: enforce the configured issuer
		validatorOpts = append(validatorOpts, validator.WithIssuer(issuer))
	}

	v, err := validator.New(validatorOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}

	var tv jwt.TokenValidator = &auth0Validator{
		v:                  v,
		issuer:             issuer,
		enrichCustomClaims: cfg.HMACSecret != "",
	}

	if len(cfg.ClaimPredicate) > 0 {
		predicate := jwt.ParseClaimPredicates(cfg.ClaimPredicate)
		tv = &jwt.PredicateValidator{
			ParentValidator: tv,
			Predicate:       predicate,
		}
	}

	if cfg.Debug {
		tv = &validatorDebugger{TokenValidator: tv, logger: zerolog.Nop()}
	}

	return tv, nil
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

type auth0Validator struct {
	v                  *validator.Validator
	issuer             string
	enrichCustomClaims bool
}

func (v *auth0Validator) ValidateToken(ctx context.Context, tokenString string) (any, error) {
	claims, err := v.v.ValidateToken(ctx, tokenString)
	if err != nil || !v.enrichCustomClaims {
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

func (v *auth0Validator) String() string {
	return fmt.Sprintf("Auth0Validator(%s)", v.issuer)
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

package oidc

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/rs/zerolog"

	"github.com/dioad/auth/jwt"
)

// TokenValidator is an alias for jwt.TokenValidator.
type TokenValidator = jwt.TokenValidator

// ValidatorOpt configures validator creation.
type ValidatorOpt func(*validatorOptions)

type validatorOptions struct {
	keyFunc      func(context.Context) (any, error)
	jwksProvider *jwks.CachingProvider
}

// WithValidatorKeyFunc sets a custom key function for validation.
func WithValidatorKeyFunc(keyFunc func(context.Context) (any, error)) ValidatorOpt {
	return func(o *validatorOptions) {
		if keyFunc != nil {
			o.keyFunc = keyFunc
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
	if cfg.Issuer == "" && cfg.URL != "" {
		// For now, use the URL as issuer if not provided
		cfg.Issuer = cfg.URL
	}

	algorithm := validator.SignatureAlgorithm(cfg.SignatureAlgorithm)

	options := &validatorOptions{}
	for _, opt := range opts {
		opt(options)
	}

	// Static HMAC secret short-circuits JWKS discovery. Intended for local
	// development / smoke tests only.
	if cfg.HMACSecret != "" && options.keyFunc == nil {
		secret := []byte(cfg.HMACSecret)
		options.keyFunc = func(_ context.Context) (any, error) { return secret, nil }
		if algorithm == "" {
			algorithm = validator.HS256
		}
		// A synthetic issuer is required by the validator library but is not
		// meaningful when using a static secret. Allow callers to omit it.
		if cfg.Issuer == "" {
			cfg.Issuer = "local-smoke"
		}
	}

	if cfg.Issuer == "" {
		return nil, fmt.Errorf("issuer or URL must be provided")
	}

	if algorithm == "" {
		algorithm = validator.RS256
	}

	if options.keyFunc == nil {
		issuerURL, err := url.Parse(cfg.Issuer)
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

	v, err := validator.New(
		validator.WithKeyFunc(options.keyFunc),
		validator.WithAlgorithm(algorithm),
		validator.WithIssuer(cfg.Issuer),
		validator.WithAudiences(cfg.Audiences),
		validator.WithAllowedClockSkew(time.Duration(cfg.AllowedClockSkew)*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}

	var tv jwt.TokenValidator = &auth0Validator{v: v, issuer: cfg.Issuer}

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

type auth0Validator struct {
	v      *validator.Validator
	issuer string
}

func (v *auth0Validator) ValidateToken(ctx context.Context, tokenString string) (any, error) {
	return v.v.ValidateToken(ctx, tokenString)
}

func (v *auth0Validator) String() string {
	return fmt.Sprintf("Auth0Validator(%s)", v.issuer)
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

type DebuggerOpt func(*validatorDebugger)

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

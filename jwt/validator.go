package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

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
func NewValidatorFromConfig(cfg *ValidatorConfig) (TokenValidator, error) {
	return NewValidatorFromConfigWithOptions(cfg)
}

// NewValidatorFromConfigWithOptions creates a TokenValidator from a ValidatorConfig using custom options.
func NewValidatorFromConfigWithOptions(cfg *ValidatorConfig, opts ...ValidatorOpt) (TokenValidator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("validator config is nil")
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("issuer must be provided")
	}

	algorithm := jwtvalidator.SignatureAlgorithm(cfg.SignatureAlgorithm)
	if algorithm == "" {
		algorithm = jwtvalidator.RS256
	}

	allowedClockSkew := time.Duration(cfg.AllowedClockSkew) * time.Second
	if allowedClockSkew <= 0 {
		allowedClockSkew = time.Minute
	}

	options := &validatorOptions{}
	for _, opt := range opts {
		opt(options)
	}

	if options.keyFunc == nil {
		cacheTTL := time.Duration(cfg.CacheTTL) * time.Second
		if cacheTTL <= 0 {
			cacheTTL = 5 * time.Minute
		}
		issuerURL, err := url.Parse(cfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("invalid issuer URL: %w", err)
		}
		if options.jwksProvider == nil {
			options.jwksProvider = jwks.NewCachingProvider(issuerURL, cacheTTL)
		}
		options.keyFunc = options.jwksProvider.KeyFunc
	}
	if options.keyFunc == nil {
		return nil, fmt.Errorf("key function not configured")
	}

	v, err := jwtvalidator.New(
		options.keyFunc,
		algorithm,
		cfg.Issuer,
		cfg.Audiences,
		jwtvalidator.WithAllowedClockSkew(allowedClockSkew),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}

	var tv TokenValidator = &auth0Validator{v: v, issuer: cfg.Issuer}

	if len(cfg.ClaimPredicate) > 0 {
		predicate := ParseClaimPredicates(cfg.ClaimPredicate)
		tv = &PredicateValidator{
			ParentValidator: tv,
			Predicate:       predicate,
		}
	}

	if cfg.Debug {
		tv = NewValidatorDebugger(tv,
			WithLabel("issuer", cfg.Issuer),
			WithLabel("audiences", strings.Join(cfg.Audiences, ",")),
			WithLabel("signatureAlgorithm", string(algorithm)),
			WithLabel("allowedClockSkew", allowedClockSkew.String()),
		)
	}

	return tv, nil
}

// NewMultiValidatorFromConfig creates a MultiValidator from multiple configs.
func NewMultiValidatorFromConfig(configs []ValidatorConfig, opts ...ValidatorOpt) (TokenValidator, error) {
	validators, err := NewValidatorsFromConfig(configs, opts...)
	if err != nil {
		return nil, err
	}
	return &MultiValidator{Validators: validators}, nil
}

// NewValidatorsFromConfig creates multiple validators from configs.
func NewValidatorsFromConfig(configs []ValidatorConfig, opts ...ValidatorOpt) ([]TokenValidator, error) {
	validators := make([]TokenValidator, 0, len(configs))
	for _, cfg := range configs {
		v, err := NewValidatorFromConfigWithOptions(&cfg, opts...)
		if err != nil {
			return nil, fmt.Errorf("error creating validator from config: %w", err)
		}
		validators = append(validators, v)
	}
	return validators, nil
}

// MultiValidator attempts to validate tokens using multiple validators in sequence.
type MultiValidator struct {
	Validators []TokenValidator
}

func (v *MultiValidator) ValidateToken(ctx context.Context, tokenString string) (any, error) {
	var lastErr error
	var errs []string
	for _, vtor := range v.Validators {
		claims, err := vtor.ValidateToken(ctx, tokenString)
		if err == nil {
			return claims, nil
		}
		lastErr = err
		errs = append(errs, err.Error())
	}
	return nil, fmt.Errorf("token validation failed: %w (%s)", lastErr, strings.Join(errs, ", "))
}

func (v *MultiValidator) String() string {
	names := make([]string, len(v.Validators))
	for i, vtor := range v.Validators {
		names[i] = vtor.String()
	}
	return fmt.Sprintf("MultiValidator(%s)", strings.Join(names, ", "))
}

// PredicateValidator wraps a TokenValidator and applies additional claim predicate validation.
type PredicateValidator struct {
	ParentValidator TokenValidator
	Predicate       ClaimPredicate
}

func (v *PredicateValidator) ValidateToken(ctx context.Context, tokenString string) (any, error) {
	claims, err := v.ParentValidator.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	var mapClaims jwt.MapClaims
	if _, ok := claims.(*jwtvalidator.ValidatedClaims); ok {
		mapClaims, err = extractClaimsMap(tokenString)
		if err != nil {
			return nil, fmt.Errorf("error extracting claims map: %w", err)
		}
	} else if mc, ok := claims.(jwt.MapClaims); ok {
		mapClaims = mc
	} else {
		return nil, fmt.Errorf("unsupported claims type for predicate validation: %T", claims)
	}

	if !v.Predicate.Validate(mapClaims) {
		return nil, fmt.Errorf("predicate validation failed")
	}

	return claims, nil
}

func (v *PredicateValidator) String() string {
	return fmt.Sprintf("PredicateValidator(%s, %s)", v.ParentValidator, v.Predicate)
}

type auth0Validator struct {
	v      *jwtvalidator.Validator
	issuer string
}

func (v *auth0Validator) ValidateToken(ctx context.Context, tokenString string) (any, error) {
	return v.v.ValidateToken(ctx, tokenString)
}

func (v *auth0Validator) String() string {
	return fmt.Sprintf("Auth0Validator(%s)", v.issuer)
}

// ValidatorDebugger wraps a TokenValidator with debug logging capabilities.
type ValidatorDebugger struct {
	logger          zerolog.Logger
	parentValidator TokenValidator
}

// ValidatorDebugOpts is a functional option for configuring a ValidatorDebugger.
type ValidatorDebugOpts func(*ValidatorDebugger)

// WithLogger sets the logger on the validator debugger.
func WithLogger(logger zerolog.Logger) func(*ValidatorDebugger) {
	return func(v *ValidatorDebugger) {
		v.logger = logger
	}
}

// WithLabel enriches the logger with a label.
func WithLabel(key, value string) func(*ValidatorDebugger) {
	return func(v *ValidatorDebugger) {
		v.logger = v.logger.With().Str(key, value).Logger()
	}
}

// NewValidatorDebugger wraps a TokenValidator with debug logging.
func NewValidatorDebugger(validator TokenValidator, opts ...ValidatorDebugOpts) *ValidatorDebugger {
	v := &ValidatorDebugger{
		parentValidator: validator,
		logger:          zerolog.Nop(),
	}

	for _, o := range opts {
		o(v)
	}

	return v
}

func (v *ValidatorDebugger) ValidateToken(ctx context.Context, tokenString string) (any, error) {
	tokenDetails, err := decodeTokenData(tokenString)
	if err != nil {
		return nil, fmt.Errorf("error decoding token data: %w", err)
	}

	v.logger.Debug().
		Stringer("validator", v.parentValidator).
		Interface("decoded_token", tokenDetails).
		Msg("decoded token")
	claims, err := v.parentValidator.ValidateToken(ctx, tokenString)
	if err != nil {
		v.logger.Error().Err(err).Msg("error validating token")
	}
	return claims, err
}

func (v *ValidatorDebugger) String() string {
	return fmt.Sprintf("ValidatorDebugger(%v)", v.parentValidator)
}

func decodeTokenData(accessToken string) (any, error) {
	tokenParts := strings.Split(accessToken, ".")
	if len(tokenParts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	var tokenData map[string]any
	if err := json.Unmarshal(payload, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token payload: %w", err)
	}

	if expiry, ok := tokenData["exp"].(float64); ok {
		tokenData["exp_datetime"] = time.Unix(int64(expiry), 0)
	}

	if issuedAt, ok := tokenData["iat"].(float64); ok {
		tokenData["iat_datetime"] = time.Unix(int64(issuedAt), 0)
	}

	if notBefore, ok := tokenData["nbf"].(float64); ok {
		tokenData["nbf_datetime"] = time.Unix(int64(notBefore), 0)
	}

	return tokenData, nil
}

// Internal helper (simplified from net/oidc/util.go)
func extractClaimsMap(tokenString string) (jwt.MapClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	return token.Claims.(jwt.MapClaims), nil
}

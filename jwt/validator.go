package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"strings"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/jwks"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
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

	algorithms, err := ResolveSignatureAlgorithms(
		cfg.SignatureAlgorithm,
		cfg.SignatureAlgorithms,
		DefaultSignatureAlgorithms(),
	)
	if err != nil {
		return nil, fmt.Errorf("resolving signature algorithms: %w", err)
	}

	allowedClockSkew := ResolveAllowedClockSkew(cfg.AllowedClockSkew)

	options := &validatorOptions{}
	for _, opt := range opts {
		opt(options)
	}

	if options.keyFunc == nil {
		keyFunc, provider, err := ResolveKeyFunc(cfg.Issuer, time.Duration(cfg.CacheTTL)*time.Second, options.jwksProvider)
		if err != nil {
			return nil, err
		}
		options.keyFunc = keyFunc
		options.jwksProvider = provider
	}

	validatorOpts := []jwtvalidator.Option{
		jwtvalidator.WithKeyFunc(options.keyFunc),
		jwtvalidator.WithIssuer(cfg.Issuer),
		jwtvalidator.WithAudiences(cfg.Audiences),
		jwtvalidator.WithAllowedClockSkew(allowedClockSkew),
	}
	if len(algorithms) == 1 {
		validatorOpts = append(validatorOpts, jwtvalidator.WithAlgorithm(algorithms[0]))
	} else {
		validatorOpts = append(validatorOpts, jwtvalidator.WithAlgorithms(algorithms))
	}

	v, err := jwtvalidator.New(validatorOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}

	tv := NewAuth0Validator(v, cfg.Issuer)

	return WrapValidator(tv, cfg.ClaimPredicate, cfg.Debug,
		WithLabel("issuer", cfg.Issuer),
		WithLabel("audiences", strings.Join(cfg.Audiences, ",")),
		WithLabel("signatureAlgorithms", SignatureAlgorithmsLabel(algorithms)),
		WithLabel("allowedClockSkew", allowedClockSkew.String()),
	), nil
}

// ResolveAllowedClockSkew converts a configured clock-skew value in seconds
// to a Duration, defaulting to one minute when unset or non-positive.
func ResolveAllowedClockSkew(configuredSeconds int) time.Duration {
	allowedClockSkew := time.Duration(configuredSeconds) * time.Second
	if allowedClockSkew <= 0 {
		allowedClockSkew = time.Minute
	}
	return allowedClockSkew
}

// ResolveKeyFunc returns a key function backed by a JWKS caching provider for
// issuer, reusing provider when it is already set rather than constructing a
// new one. cacheTTL non-positive defaults to five minutes. Returns the
// resolved provider so callers that need to reuse it can do so. Shared by jwt
// and oidc validator construction so both packages resolve signing keys via
// the same JWKS-discovery path.
func ResolveKeyFunc(issuer string, cacheTTL time.Duration, provider *jwks.CachingProvider) (func(context.Context) (any, error), *jwks.CachingProvider, error) {
	if provider != nil {
		return provider.KeyFunc, provider, nil
	}

	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid issuer URL: %w", err)
	}
	if cacheTTL <= 0 {
		cacheTTL = 5 * time.Minute
	}

	provider, err = jwks.NewCachingProvider(
		jwks.WithIssuerURL(issuerURL),
		jwks.WithCacheTTL(cacheTTL),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create JWKS caching provider: %w", err)
	}
	return provider.KeyFunc, provider, nil
}

// NewAuth0Validator wraps an already-configured auth0/go-jwt-middleware
// Validator as a TokenValidator. Exported so packages that build their own
// jwtvalidator.Option pipeline (e.g. oidc, for HMAC/custom-claims support)
// can still produce the canonical TokenValidator wrapper instead of
// duplicating its type.
func NewAuth0Validator(v *jwtvalidator.Validator, issuer string) TokenValidator {
	return &auth0Validator{v: v, issuer: issuer}
}

// WrapValidator layers optional claim-predicate and debug-logging wrappers
// onto tv, in that order, mirroring the config-driven wrapping pipeline used
// by NewValidatorFromConfigWithOptions. Shared by jwt and oidc validator
// construction so both packages apply claim_predicates/debug identically.
func WrapValidator(tv TokenValidator, claimPredicate map[string]any, debug bool, debugOpts ...ValidatorDebugOpts) TokenValidator {
	if len(claimPredicate) > 0 {
		tv = &PredicateValidator{
			ParentValidator: tv,
			Predicate:       ParseClaimPredicates(claimPredicate),
		}
	}
	if debug {
		tv = NewValidatorDebugger(tv, debugOpts...)
	}
	return tv
}

// SignatureAlgorithmsLabel renders algorithms as a comma-separated string for
// debug-log labels.
func SignatureAlgorithmsLabel(algorithms []jwtvalidator.SignatureAlgorithm) string {
	values := make([]string, 0, len(algorithms))
	for _, algorithm := range algorithms {
		values = append(values, string(algorithm))
	}
	return strings.Join(values, ",")
}

// NewMultiValidatorFromConfig creates a MultiValidator from multiple configs.
func NewMultiValidatorFromConfig(configs []ValidatorConfig, opts ...ValidatorOpt) (TokenValidator, error) {
	validators, err := NewValidatorsFromConfig(configs, opts...)
	if err != nil {
		return nil, err
	}
	return &MultiValidator{Validators: validators}, nil
}

func NewMultiValidator(validators ...TokenValidator) TokenValidator {
	return &MultiValidator{Validators: validators}
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

	mapClaims, err := extractClaimsMap(tokenString)
	if err != nil {
		switch c := claims.(type) {
		case jwt.MapClaims:
			mapClaims = c
		case map[string]any:
			mapClaims = jwt.MapClaims(c)
		case *jwtvalidator.ValidatedClaims:
			// Build mapClaims from the already-validated claim data as a fallback.
			mapClaims, err = validatedClaimsToMapClaims(c)
			if err != nil {
				return nil, fmt.Errorf("building claims map from validated claims: %w", err)
			}
		default:
			return nil, fmt.Errorf("unsupported claims type for predicate validation: %T", claims)
		}
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

// validatedClaimsToMapClaims converts a *jwtvalidator.ValidatedClaims to jwt.MapClaims
// by merging registered claims and any custom claims via JSON round-trip.
func validatedClaimsToMapClaims(vc *jwtvalidator.ValidatedClaims) (jwt.MapClaims, error) {
	m := jwt.MapClaims{}

	rc := vc.RegisteredClaims
	if rc.Issuer != "" {
		m["iss"] = rc.Issuer
	}
	if rc.Subject != "" {
		m["sub"] = rc.Subject
	}
	if len(rc.Audience) > 0 {
		m["aud"] = rc.Audience
	}
	if rc.Expiry != 0 {
		m["exp"] = rc.Expiry
	}
	if rc.NotBefore != 0 {
		m["nbf"] = rc.NotBefore
	}
	if rc.IssuedAt != 0 {
		m["iat"] = rc.IssuedAt
	}
	if rc.ID != "" {
		m["jti"] = rc.ID
	}

	if vc.CustomClaims != nil {
		b, err := json.Marshal(vc.CustomClaims)
		if err != nil {
			return nil, fmt.Errorf("marshaling custom claims: %w", err)
		}
		var customMap map[string]any
		if err := json.Unmarshal(b, &customMap); err != nil {
			return nil, fmt.Errorf("unmarshaling custom claims: %w", err)
		}
		maps.Copy(m, customMap)
	}

	return m, nil
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

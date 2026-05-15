// Package auth provides server-side identity and authorization logic.
//
// # Principal Extraction
//
// The PrincipalExtractor interface provides centralized principal (user identity) extraction
// from HTTP requests. This is the single source of truth for determining "who" is making a request.
//
// Architecture:
//   - Single interface (PrincipalExtractor) for all principal extraction
//   - Multiple sources implement PrincipalSource interface
//   - Fallback chain: Fly.io → GitHub Actions → AWS → generic OIDC → JWT → GitHub
//   - Returns principal context with identifier, source metadata, and any errors
//
// Usage Example:
//
//	extractor := auth.NewDefaultPrincipalExtractor()
//	ctx, err := extractor.ExtractPrincipal(req.Context(), req)
//	if err != nil {
//	    // Handle no principal found
//	    return
//	}
//	// Use ctx.ID and ctx.Source for logging/auditing
//	log.Info("principal", ctx.ID, "source", ctx.Source)
//
// Adding New Sources:
//
// To add a new principal source (e.g., mTLS certificates):
//  1. Implement the PrincipalSource interface
//  2. Add to the sources slice in NewDefaultPrincipalExtractor
//  3. Update tests to cover the new source
//
// Testing:
//
// Use mock extractors in tests to avoid needing real authentication:
//
//	type mockExtractor struct{ principal string }
//	func (m *mockExtractor) ExtractPrincipal(ctx context.Context, r *http.Request) (*PrincipalContext, error) {
//	    return &PrincipalContext{ID: m.principal, Source: "mock"}, nil
//	}
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"

	"github.com/rs/zerolog/log"

	authcontext "github.com/dioad/auth/http/context"
	dnag "github.com/dioad/auth/http/github"
	"github.com/dioad/auth/jwt"
	"github.com/dioad/auth/oidc"
	"github.com/dioad/auth/oidc/aws"
	"github.com/dioad/auth/oidc/flyio"
	"github.com/dioad/auth/oidc/githubactions"
)

var (
	ErrNoPrincipalFound = errors.New("no principal found")
)

// PrincipalContext contains metadata about how a principal was extracted.
// This is useful for debugging, logging, and auditing authentication decisions.
type PrincipalContext struct {
	// ID identifies the principal
	ID string

	// Source identifies which authentication method was used (e.g., "jwt", "oidc", "github")
	Source string

	// TenantID identifies a principal's tenant
	TenantID string

	// Attributes contains additional authentication data for debugging/logging
	Attributes map[string]any

	// Roles contains a list of roles associated with the principal
	Roles []string

	// IsService indicates if the principal represents a service / system
	IsService bool
}

func (c *PrincipalContext) HasRole(role string) bool {
	if c == nil {
		return false
	}
	return slices.Contains(c.Roles, role)
}

type contextKeyPrincipalContext struct{}

// ContextWithPrincipalContext stores a PrincipalContext in the request context.
func ContextWithPrincipalContext(ctx context.Context, principalCtx *PrincipalContext) context.Context {
	return context.WithValue(ctx, contextKeyPrincipalContext{}, principalCtx)
}

// PrincipalContextFromContext retrieves a PrincipalContext from the request context.
func PrincipalContextFromContext(ctx context.Context) *PrincipalContext {
	val := ctx.Value(contextKeyPrincipalContext{})
	if pc, ok := val.(*PrincipalContext); ok {
		return pc
	}
	return nil
}

// PrincipalExtractor extracts the authenticated principal (user identity) from an HTTP request.
// This is the central service for all principal/identity resolution in the server.
//
// The extractor tries multiple sources in priority order and returns the first
// successful match, along with metadata about how the principal was determined.
type PrincipalExtractor interface {
	// ExtractPrincipal attempts to extract a principal from the request context.
	// Returns the principal context about the extraction, or an error if no principal found.
	ExtractPrincipal(ctx context.Context, r *http.Request) (*PrincipalContext, error)
}

// PrincipalSource represents a single method of extracting a principal from a request.
// Each source (JWT, OIDC, GitHub, etc.) implements this interface.
type PrincipalSource interface {
	// Extract attempts to extract a principal from this source.
	// Returns the principal identifier or empty string if not available.
	Extract(ctx context.Context, r *http.Request) (string, error)

	// Name returns the identifier for this source (e.g., "jwt", "oidc", "github")
	Name() string

	// Claims returns additional authentication data for debugging/logging
	Claims(ctx context.Context) map[string]any

	// Roles return the roles asserted by this source, or nil if unavailable.  This is used for role-based privilege assignment.
	Roles(ctx context.Context) []string

	// IsService returns if the source is a service identity
	IsService(ctx context.Context) bool
}

// jwtPrincipalSource extracts principal from JWT token claims via auth/http/context package
type jwtPrincipalSource struct {
	// RoleMapper maps generic JWT claims to internal roles.
	// When nil, provider-supplied roles from claim maps are still returned.
	RoleMapper ClaimRoleMapper
}

func (s *jwtPrincipalSource) Extract(ctx context.Context, _ *http.Request) (string, error) {
	principal, _ := authcontext.AuthenticatedPrincipalFromContext(ctx)
	return principal, nil
}

func (s *jwtPrincipalSource) Name() string {
	return "jwt"
}

func (s *jwtPrincipalSource) Claims(ctx context.Context) map[string]any {
	result := make(map[string]any)

	principal, ok := authcontext.AuthenticatedPrincipalFromContext(ctx)
	if ok {
		result["principal"] = principal
	}

	if registered, ok := authcontext.AuthenticatedRegisteredClaimsFromContext(ctx); ok {
		if registered.Subject != "" {
			result["sub"] = registered.Subject
		}
		if registered.Issuer != "" {
			result["iss"] = registered.Issuer
		}
		if len(registered.Audience) > 0 {
			result["aud"] = []string(registered.Audience)
		}
	}

	if custom, ok := authcontext.AuthenticatedCustomClaimsFromContext(ctx); ok {
		for key, value := range custom {
			result[key] = value
		}
	}

	// Keep compatibility with middleware paths that only store ValidatedClaims.
	for key, value := range genericClaimsFromValidatedContext(ctx) {
		result[key] = value
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func (s *jwtPrincipalSource) Roles(ctx context.Context) []string {
	claims := s.Claims(ctx)
	roles := extractRolesFromClaimsMap(claims)
	if s.RoleMapper != nil {
		roles = append(roles, s.RoleMapper.MapRoles(claims)...)
	}
	return dedupeStrings(roles)
}

func (s *jwtPrincipalSource) IsService(_ context.Context) bool { return false }

// oidcPrincipalSource extracts principal from OIDC IntrospectionResponse claims.
type oidcPrincipalSource struct {
	// RoleMapper maps generic OIDC claims to internal roles.
	// When nil, provider-supplied roles from realm_access (and top-level roles
	// in generic claim maps) are still returned.
	RoleMapper ClaimRoleMapper
}

func (s *oidcPrincipalSource) Roles(ctx context.Context) []string {
	var roles []string
	claims := jwt.CustomClaimsFromContext[*oidc.IntrospectionResponse](ctx)
	if claims != nil {
		roles = append(roles, claims.RealmAccess.Roles...)
	} else {
		roles = append(roles, extractRolesFromClaimsMap(genericClaimsFromValidatedContext(ctx))...)
	}
	if s.RoleMapper != nil {
		roles = append(roles, s.RoleMapper.MapRoles(s.Claims(ctx))...)
	}
	return dedupeStrings(roles)
}

func (s *oidcPrincipalSource) Extract(ctx context.Context, _ *http.Request) (string, error) {
	// Try standard OIDC IntrospectionResponse claims first
	claims := jwt.CustomClaimsFromContext[*oidc.IntrospectionResponse](ctx)
	if claims != nil && claims.Subject != "" {
		return claims.Subject, nil
	}
	// Fallback only for generic validated claims that look OIDC-like.
	if generic := genericClaimsFromValidatedContext(ctx); generic != nil {
		if sub, ok := generic["sub"].(string); ok && sub != "" && hasOIDCLikeClaims(generic) {
			return sub, nil
		}
	}
	return "", nil
}

func (s *oidcPrincipalSource) Name() string {
	return "oidc"
}

func (s *oidcPrincipalSource) Claims(ctx context.Context) map[string]any {
	result := make(map[string]any)

	// Check standard OIDC claims
	claims := jwt.CustomClaimsFromContext[*oidc.IntrospectionResponse](ctx)

	if claims != nil {
		result[AttrUserPrincipalName] = claims.UserPrincipalName
		result[AttrPreferredUsername] = claims.PreferredUsername
		result[AttrEmail] = claims.Email
		result[AttrEmailVerified] = claims.EmailVerified
		result[AttrUsername] = claims.Username
		result["active"] = claims.Active
		result[AttrOrganisations] = claims.Organisations
		// Also expose common raw OIDC/JWT claim names so mapping rules can use
		// either canonical or provider-native keys.
		result["upn"] = claims.UserPrincipalName
		result["preferred_username"] = claims.PreferredUsername
		result["email"] = claims.Email
		result["email_verified"] = claims.EmailVerified
		result["username"] = claims.Username
		result["org"] = claims.Organisations
		return result
	}

	// Fallback for validators that store custom claims as generic maps rather
	// than oidc.IntrospectionResponse.
	maps.Copy(result, genericClaimsFromValidatedContext(ctx))

	return result
}

func (s *oidcPrincipalSource) IsService(ctx context.Context) bool {
	claims := jwt.CustomClaimsFromContext[*oidc.IntrospectionResponse](ctx)
	if claims != nil {
		return claims.TokenType != "Bearer"
	}
	return false
}

// githubPrincipalSource extracts principal from GitHub user info
type githubPrincipalSource struct{}

func (s *githubPrincipalSource) Extract(ctx context.Context, _ *http.Request) (string, error) {
	userInfo := dnag.GitHubUserInfoFromContext(ctx)
	if userInfo == nil {
		return "", nil
	}

	return userInfo.Login, nil
}

func (s *githubPrincipalSource) Name() string {
	return "github"
}

func (s *githubPrincipalSource) Claims(ctx context.Context) map[string]any {
	userInfo := dnag.GitHubUserInfoFromContext(ctx)
	if userInfo == nil {
		return nil
	}

	result := make(map[string]any)
	if userInfo.Login != "" {
		result["login"] = userInfo.Login
	}
	if userInfo.PrimaryEmail != "" {
		result[AttrEmail] = userInfo.PrimaryEmail
	}

	return result
}

func (s *githubPrincipalSource) Roles(_ context.Context) []string { return nil }

func (s *githubPrincipalSource) IsService(_ context.Context) bool { return false }

// defaultPrincipalExtractor implements PrincipalExtractor with a fallback chain
type defaultPrincipalExtractor struct {
	sources []PrincipalSource
}

// ExtractPrincipal tries each source in order and returns the first successful match.
// The ctx parameter must equal r.Context() to ensure claims stored on the request
// context (by middleware) are available to the sources. Use r.Context() rather
// than a separate context parameter when calling this method.
func (e *defaultPrincipalExtractor) ExtractPrincipal(ctx context.Context, r *http.Request) (*PrincipalContext, error) {
	// Use request context if available to ensure claims stored by middleware are accessible
	if r != nil && r.Context() != ctx {
		ctx = r.Context()
	}

	for _, source := range e.sources {
		principal, err := source.Extract(ctx, r)
		if err != nil {
			// Log the error at trace level for debugging, but continue to next source
			// This allows fallback to continue even if a source has issues
			log.Trace().
				Err(err).
				Str("source", source.Name()).
				Msg("principal source returned error, continuing to next source")
			continue
		}

		if principal != "" {
			// Found a principal, return it with context
			return &PrincipalContext{
				ID:         principal,
				Source:     source.Name(),
				Attributes: source.Claims(ctx),
				Roles:      source.Roles(ctx),
				IsService:  source.IsService(ctx),
			}, nil
		}
	}

	// No principal found from any source - generate error message dynamically
	sourceNames := make([]string, len(e.sources))
	for i, source := range e.sources {
		sourceNames[i] = source.Name()
	}
	return nil, fmt.Errorf("%w: tried sources %v", ErrNoPrincipalFound, sourceNames)
}

// DefaultExtractorConfig configures per-source ClaimRoleMappers for
// NewDefaultPrincipalExtractorWithConfig. A nil mapper disables only mapped-role
// additions; provider-native source roles are still returned by each source.
type DefaultExtractorConfig struct {
	// FlyioMapper maps Fly.io OIDC claims to internal roles.
	FlyioMapper ClaimRoleMapper
	// GithubActionsMapper maps GitHub Actions OIDC claims to internal roles.
	GithubActionsMapper ClaimRoleMapper
	// AWSMapper maps AWS OIDC claims to internal roles.
	AWSMapper ClaimRoleMapper
	// OIDCMapper maps generic OIDC claims (e.g. Dex/Keycloak user tokens) to
	// internal roles.
	OIDCMapper ClaimRoleMapper
	// JWTMapper maps generic JWT claims stored by auth middleware to internal
	// roles.
	JWTMapper ClaimRoleMapper
}

// NewDefaultPrincipalExtractor creates a PrincipalExtractor with the standard fallback chain:
// 1. Fly.io OIDC token
// 2. GitHub Actions OIDC token
// 3. AWS OIDC token
// 4. Generic OIDC token (Keycloak, etc.)
// 5. JWT token
// 6. GitHub user info (lowest priority)
//
// This matches the existing behavior of the system.
func NewDefaultPrincipalExtractor() PrincipalExtractor {
	return NewDefaultPrincipalExtractorWithConfig(DefaultExtractorConfig{})
}

// NewDefaultPrincipalExtractorWithConfig creates a PrincipalExtractor with the standard
// fallback chain and per-source ClaimRoleMappers from cfg.
func NewDefaultPrincipalExtractorWithConfig(cfg DefaultExtractorConfig) PrincipalExtractor {
	return NewPrincipalExtractor(
		&flyio.PrincipalSource{RoleMapper: cfg.FlyioMapper},
		&githubactions.PrincipalSource{RoleMapper: cfg.GithubActionsMapper},
		&aws.PrincipalSource{RoleMapper: cfg.AWSMapper},
		&oidcPrincipalSource{RoleMapper: cfg.OIDCMapper},
		&jwtPrincipalSource{RoleMapper: cfg.JWTMapper},
		&githubPrincipalSource{},
	)
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func genericClaimsFromValidatedContext(ctx context.Context) map[string]any {
	vc := jwt.ValidatedClaimsFromContext(ctx)
	if vc == nil {
		return nil
	}

	result := map[string]any{}
	if vc.RegisteredClaims.Subject != "" {
		result["sub"] = vc.RegisteredClaims.Subject
	}
	if vc.RegisteredClaims.Issuer != "" {
		result["iss"] = vc.RegisteredClaims.Issuer
	}
	if len(vc.RegisteredClaims.Audience) > 0 {
		result["aud"] = []string(vc.RegisteredClaims.Audience)
	}

	if vc.CustomClaims == nil {
		return result
	}

	// Best-effort fallback for structured custom claims.
	raw, err := json.Marshal(vc.CustomClaims)
	if err != nil {
		return result
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		return result
	}
	maps.Copy(result, asMap)
	return result
}

func hasOIDCLikeClaims(claims map[string]any) bool {
	if len(claims) == 0 {
		return false
	}

	for _, key := range []string{
		"auth_time",
		"acr",
		"amr",
		"azp",
		"nonce",
		"email",
		"preferred_username",
		"given_name",
		"family_name",
		"name",
		"realm_access",
		"roles",
	} {
		if _, ok := claims[key]; ok {
			return true
		}
	}
	return false
}

func extractRolesFromClaimsMap(claims map[string]any) []string {
	if len(claims) == 0 {
		return nil
	}
	var roles []string

	if realmAccess, ok := claims["realm_access"].(map[string]any); ok {
		roles = append(roles, toStringSlice(realmAccess["roles"])...)
	}
	roles = append(roles, toStringSlice(claims["roles"])...)

	return dedupeStrings(roles)
}

func toStringSlice(value any) []string {
	switch raw := value.(type) {
	case []string:
		return dedupeStrings(raw)
	case []any:
		out := make([]string, 0, len(raw))
		for _, item := range raw {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return dedupeStrings(out)
	default:
		return nil
	}
}

// NewPrincipalExtractor creates a PrincipalExtractor with the provided sources, in order
func NewPrincipalExtractor(sources ...PrincipalSource) PrincipalExtractor {
	return &defaultPrincipalExtractor{
		sources: sources,
	}
}

// NewAllowAllPrincipalExtractor creates a PrincipalExtractor that accepts all requests as unauthenticated.
// Useful for testing and development environments where authorization is disabled.
func NewAllowAllPrincipalExtractor() PrincipalExtractor {
	return NewPrincipalExtractor(&allowAllPrincipalSource{})
}

type allowAllPrincipalSource struct{}

func (s *allowAllPrincipalSource) Extract(_ context.Context, _ *http.Request) (string, error) {
	return "unauthenticated", nil
}

func (s *allowAllPrincipalSource) Name() string {
	return "allow-all"
}

func (s *allowAllPrincipalSource) Claims(_ context.Context) map[string]any {
	return make(map[string]any)
}

func (s *allowAllPrincipalSource) Roles(_ context.Context) []string {
	return nil
}

func (s *allowAllPrincipalSource) IsService(_ context.Context) bool {
	return true
}

// MockPrincipalSource is a test implementation of PrincipalSource
type MockPrincipalSource struct {
	MockName      string
	MockPrincipal string
	MockError     error
	MockClaims    map[string]any
	MockRoles     []string
	MockIsService bool
}

func (m *MockPrincipalSource) Extract(_ context.Context, _ *http.Request) (string, error) {
	return m.MockPrincipal, m.MockError
}

func (m *MockPrincipalSource) Name() string {
	if m.MockName == "" {
		return "mock"
	}
	return m.MockName
}

func (m *MockPrincipalSource) Claims(_ context.Context) map[string]any {
	return m.MockClaims
}

func (m *MockPrincipalSource) Roles(_ context.Context) []string {
	return m.MockRoles
}

func (m *MockPrincipalSource) IsService(_ context.Context) bool { return m.MockIsService }

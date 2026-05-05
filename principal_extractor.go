// Package oidc provides server-side business logic and services.
//
// # Principal Extraction
//
// The PrincipalExtractor interface provides centralized principal (user identity) extraction
// from HTTP requests. This is the single source of truth for determining "who" is making a request.
//
// Architecture:
//   - Single interface (PrincipalExtractor) for all principal extraction
//   - Multiple sources (JWT, OIDC, GitHub) implement PrincipalSource interface
//   - Fallback chain: JWT → OIDC → GitHub (matches existing system behavior)
//   - Returns principal identifier, source metadata, and any errors
//
// Usage Example:
//
//	extractor := service.NewDefaultPrincipalExtractor()
//	principal, ctx, err := extractor.ExtractPrincipal(req.Context(), req)
//	if err != nil {
//	    // Handle no principal found
//	    return
//	}
//	// Use principal and ctx.Source for logging/auditing
//	log.Info("principal", principal, "source", ctx.Source)
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
//	func (m *mockExtractor) ExtractPrincipal(ctx context.Context, r *http.Request) (string, *PrincipalContext, error) {
//	    return m.principal, &PrincipalContext{Source: "mock"}, nil
//	}
package auth

import (
	"context"
	"errors"
	"fmt"
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

	// InService indicates if the principal represents a service / system
	IsService bool
}

func (c *PrincipalContext) HasRole(role string) bool {
	if c == nil {
		return false
	}
	return slices.Contains(c.Roles, role)
}

type contextKeyPrincipalContext struct{}

func ContextWithPrincipalContext(ctx context.Context, privileges *PrincipalContext) context.Context {
	return context.WithValue(ctx, contextKeyPrincipalContext{}, privileges)
}

func PrincipalContextFromContext(ctx context.Context) *PrincipalContext {
	val := ctx.Value(contextKeyPrincipalContext{})
	if val != nil {
		return val.(*PrincipalContext)
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

// jwtPrincipalSource extracts principal from JWT token claims via dcac package
type jwtPrincipalSource struct{}

func (s *jwtPrincipalSource) Extract(ctx context.Context, _ *http.Request) (string, error) {
	principal, _ := authcontext.AuthenticatedPrincipalFromContext(ctx)
	return principal, nil
}

func (s *jwtPrincipalSource) Name() string {
	return "jwt"
}

func (s *jwtPrincipalSource) Claims(ctx context.Context) map[string]any {
	// JWT claims are not directly exposed through the authcontext package
	// Return minimal information
	principal, ok := authcontext.AuthenticatedPrincipalFromContext(ctx)
	if ok {
		return map[string]any{
			"principal": principal,
		}
	}
	return nil
}

func (s *jwtPrincipalSource) Roles(_ context.Context) []string {
	return nil
}

func (s *jwtPrincipalSource) IsService(_ context.Context) bool { return false }

// oidcPrincipalSource extracts principal from OIDC IntrospectionResponse claims
type oidcPrincipalSource struct{}

func (s *oidcPrincipalSource) Roles(ctx context.Context) []string {
	claims := jwt.CustomClaimsFromContext[*oidc.IntrospectionResponse](ctx)
	if claims != nil {
		return claims.RealmAccess.Roles
	}
	return nil
}

func (s *oidcPrincipalSource) Extract(ctx context.Context, _ *http.Request) (string, error) {
	// Try standard OIDC IntrospectionResponse claims first
	claims := jwt.CustomClaimsFromContext[*oidc.IntrospectionResponse](ctx)
	// if claims != nil {
	// 	// Try different claim fields in priority order
	// 	if claims.UserPrincipalName != "" {
	// 		return claims.UserPrincipalName, nil
	// 	}
	// 	if claims.PreferredUsername != "" {
	// 		return claims.PreferredUsername, nil
	// 	}
	// 	if claims.AWSCustomClaims.HttpsStsAmazonawsCom.PrincipalId != "" {
	// 		return claims.AWSCustomClaims.HttpsStsAmazonawsCom.PrincipalId, nil
	// 	}
	// }

	if claims != nil {
		return claims.Subject, nil
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
		result["user_principal_name"] = claims.UserPrincipalName
		result["preferred_username"] = claims.PreferredUsername
		result["primary_email"] = claims.Email
		result["primary_email_verified"] = claims.EmailVerified
		result["username"] = claims.Username
		result["active"] = claims.Active
		result["organisation"] = claims.Organisation
	}

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
		result["primary_email"] = userInfo.PrimaryEmail
	}

	return result
}

func (s *githubPrincipalSource) Roles(_ context.Context) []string { return nil }

func (s *githubPrincipalSource) IsService(ctx context.Context) bool { return false }

// defaultPrincipalExtractor implements PrincipalExtractor with a fallback chain
type defaultPrincipalExtractor struct {
	sources []PrincipalSource
}

// ExtractPrincipal tries each source in order and returns the first successful match
func (e *defaultPrincipalExtractor) ExtractPrincipal(ctx context.Context, r *http.Request) (*PrincipalContext, error) {
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
	return nil, fmt.Errorf("%w tried sources %v", ErrNoPrincipalFound, sourceNames)
}

// DefaultExtractorConfig configures per-source ClaimRoleMappers for
// NewDefaultPrincipalExtractorWithConfig. Sources with a nil mapper return no roles
// from claims (equivalent to the zero-value behaviour of NewDefaultPrincipalExtractor).
type DefaultExtractorConfig struct {
	// FlyioMapper maps Fly.io OIDC claims to internal roles.
	FlyioMapper ClaimRoleMapper
	// GithubActionsMapper maps GitHub Actions OIDC claims to internal roles.
	GithubActionsMapper ClaimRoleMapper
	// AWSMapper maps AWS OIDC claims to internal roles.
	AWSMapper ClaimRoleMapper
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
		&oidcPrincipalSource{},
		&jwtPrincipalSource{},
		&githubPrincipalSource{},
	)
}

// NewPrincipalExtractor creates a PrincipalExtractor with the provided sources, in order
func NewPrincipalExtractor(sources ...PrincipalSource) PrincipalExtractor {
	return &defaultPrincipalExtractor{
		sources: sources,
	}
}

func NewAllowAllPrincipalExtractor() PrincipalExtractor {
	return NewPrincipalExtractor(&allowAllPrincipalSource{})
}

type allowAllPrincipalSource struct{}

func (s *allowAllPrincipalSource) Extract(ctx context.Context, r *http.Request) (string, error) {
	return "unauthenticated", nil
}

func (s *allowAllPrincipalSource) Name() string {
	return "allow-all"
}

func (s *allowAllPrincipalSource) Claims(ctx context.Context) map[string]any {
	return make(map[string]any)
}

func (s *allowAllPrincipalSource) Roles(ctx context.Context) []string {
	return nil
}

func (s *allowAllPrincipalSource) IsService(ctx context.Context) bool {
	return true
}

// MockPrincipalSource is a test implementation of PrincipalSource
type MockPrincipalSource struct {
	MockName      string
	MockPrincipal string
	MockError     error
	MockClaims    map[string]any
	MockGroups    []string
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

func (m *MockPrincipalSource) Groups(_ context.Context) []string {
	return m.MockGroups
}

func (m *MockPrincipalSource) Roles(_ context.Context) []string {
	return m.MockRoles
}

func (m *MockPrincipalSource) IsService(_ context.Context) bool { return m.MockIsService }

package auth_test

import (
	"context"
	"testing"
	"time"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth"
	"github.com/dioad/auth/oidc"
)

const keycloakTestSecret = "keycloak-shaped-token-secret"

// keycloakAccessToken signs a token with the claims a Keycloak access token
// carries: no "active" or "token_type", which only an introspection response
// has, and "aud" as given.
func keycloakAccessToken(t *testing.T, aud any) string {
	t.Helper()
	now := time.Now()
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"sub":                "fbb3f321-fbf9-4e0e-bc9f-e80f9d932a63",
		"iss":                "https://auth.example/realms/example",
		"aud":                aud,
		"azp":                "connect-cli",
		"typ":                "Bearer",
		"iat":                now.Unix(),
		"exp":                now.Add(time.Hour).Unix(),
		"auth_time":          now.Unix(),
		"scope":              "openid profile email offline_access",
		"email":              "user@example.com",
		"email_verified":     true,
		"preferred_username": "user",
		"groups":             []string{"mail"},
		"realm_access":       map[string]any{"roles": []string{"offline_access"}},
		"org":                []string{"example"},
	})
	signed, err := token.SignedString([]byte(keycloakTestSecret))
	require.NoError(t, err)
	return signed
}

// TestKeycloakAccessToken_DecodesIntoIntrospectionClaims mirrors connect's
// server: a multi validator asked for *oidc.IntrospectionResponse claims
// validates a Keycloak access token, exposes its email, and the principal
// is still the token's subject and not a service.
func TestKeycloakAccessToken_DecodesIntoIntrospectionClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		aud  any
	}{
		{name: "with a single audience", aud: "test"},
		{name: "with a list of audiences", aud: []string{"test", "account"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := oidc.ValidatorConfig{HMACSecret: keycloakTestSecret, AllowInsecureHMAC: true, Audiences: []string{"test"}}
			v, err := oidc.NewMultiValidatorFromConfig([]oidc.ValidatorConfig{cfg},
				jwtvalidator.WithCustomClaims(func() *oidc.IntrospectionResponse { return &oidc.IntrospectionResponse{} }))
			require.NoError(t, err)

			out, err := v.ValidateToken(context.Background(), keycloakAccessToken(t, tt.aud))
			require.NoError(t, err)
			vc, ok := out.(*jwtvalidator.ValidatedClaims)
			require.True(t, ok, "expected *ValidatedClaims, got %T", out)
			claims, ok := vc.CustomClaims.(*oidc.IntrospectionResponse)
			require.True(t, ok, "expected *oidc.IntrospectionResponse, got %T", vc.CustomClaims)
			assert.Equal(t, "user@example.com", claims.Email)
			assert.Equal(t, "test", claims.Audience)
			assert.Equal(t, "Bearer", claims.TokenType, "a validated JWT is a bearer token")

			ctx := simulateTypedClaimsContext(context.Background(), vc, nil)
			principal, err := auth.NewDefaultPrincipalExtractorWithConfig(auth.DefaultExtractorConfig{}).ExtractPrincipal(ctx)
			require.NoError(t, err)
			assert.Equal(t, "fbb3f321-fbf9-4e0e-bc9f-e80f9d932a63", principal.ID, "the principal is the token's subject")
			assert.False(t, principal.IsService, "a user's access token is not a service identity")
		})
	}
}

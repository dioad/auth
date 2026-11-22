package auth_test

import (
	"context"
	"testing"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth"
)

func Test_jwtPrincipalSource_Claims_canonicalEmailAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		verified     any
		wantVerified any
	}{
		{name: "bool true", verified: true, wantVerified: true},
		{name: "bool false", verified: false, wantVerified: false},
		{name: "string true is coerced", verified: "true", wantVerified: true},
		{name: "unparseable string is left as is", verified: "maybe", wantVerified: "maybe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			claims := map[string]any{
				"email":          "user@example.com",
				"email_verified": tt.verified,
			}
			vc := &jwtvalidator.ValidatedClaims{
				RegisteredClaims: jwtvalidator.RegisteredClaims{Subject: "user-1"},
			}
			ctx := simulateTypedClaimsContext(context.Background(), vc, claims)

			pc, err := auth.NewDefaultPrincipalExtractor().ExtractPrincipal(ctx)
			require.NoError(t, err)

			assert.Equal(t, "jwt", pc.Source)
			assert.Equal(t, "user@example.com", pc.Attributes[auth.AttrEmail])
			assert.Equal(t, tt.wantVerified, pc.Attributes[auth.AttrEmailVerified])
			assert.Equal(t, tt.verified, pc.Attributes["email_verified"], "raw claim must be untouched")
		})
	}
}

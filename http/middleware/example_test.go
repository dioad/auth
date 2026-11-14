package middleware_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"

	"github.com/dioad/auth"
	"github.com/dioad/auth/claimrolemapping"
	"github.com/dioad/auth/http/middleware"
	"github.com/dioad/auth/http/server"
	"github.com/dioad/auth/oidc"
)

// ExamplePrincipalExtractionHandler is the usual API chain: validate the
// bearer token, turn it into a principal with roles, and let the handler read
// the principal back from the request context.
//
// Tokens are validated with a shared secret so that the example runs without
// an identity provider. That is for local development and tests only.
func ExamplePrincipalExtractionHandler() {
	validate, err := server.OAuth2ValidatorHandler([]oidc.ValidatorConfig{{
		HMACSecret:        "example-secret",
		AllowInsecureHMAC: true,
		Audiences:         []string{"my-api"},
	}})
	if err != nil {
		fmt.Println(err)
		return
	}

	// Roles come from claims. A rule with a Source applies to that source
	// only; "oidc" is the source for a token from a generic OIDC issuer.
	extractor := claimrolemapping.BuildPrincipalExtractor(claimrolemapping.ExtractorConfig{
		ClaimRoleMappings: []claimrolemapping.ClaimRoleMappingConfig{
			{Source: claimrolemapping.SourceOIDC, Claims: map[string]string{"email": "alice@example.com"}, Role: "operator"},
		},
	}, zerolog.Nop())

	handler := validate(middleware.PrincipalExtractionHandler(extractor)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := auth.PrincipalContextFromContext(r.Context())
			_, _ = fmt.Fprintf(w, "%s via %s with roles %v", principal.ID, principal.Source, principal.Roles)
		}),
	))

	now := time.Now()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "alice",
		"iss":   "https://idp.example",
		"aud":   "my-api",
		"email": "alice@example.com",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}).SignedString([]byte("example-secret"))
	if err != nil {
		fmt.Println(err)
		return
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	fmt.Println(rr.Code, rr.Body.String())
	// Output:
	// 200 alice via oidc with roles [operator]
}

package server_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dioad/lifecycle"

	"github.com/dioad/auth/http/server"
	"github.com/dioad/auth/oidc"
)

// ExampleOAuth2ValidatorHandler protects an API with JWT validation. The
// token is read from the Authorization header only: a valid token in a cookie
// is refused, so a browser cannot be made to call the API with credentials it
// attaches by itself.
//
// The example validates tokens with a shared secret so that it runs without
// an identity provider. HMACSecret is for local development and tests only. A
// real configuration names an issuer, and the keys are fetched from it.
func ExampleOAuth2ValidatorHandler() {
	middleware, err := server.OAuth2ValidatorHandler([]oidc.ValidatorConfig{{
		HMACSecret:        "example-secret",
		AllowInsecureHMAC: true,
		Audiences:         []string{"my-api"},
	}})
	if err != nil {
		fmt.Println(err)
		return
	}

	api := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "hello")
	}))

	now := time.Now()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "alice",
		"iss": "https://idp.example",
		"aud": "my-api",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}).SignedString([]byte("example-secret"))
	if err != nil {
		fmt.Println(err)
		return
	}

	call := func(modify func(*http.Request)) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		modify(req)
		rr := httptest.NewRecorder()
		api.ServeHTTP(rr, req)
		return rr.Code
	}

	fmt.Println("bearer token:", call(func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }))
	fmt.Println("no token:", call(func(*http.Request) {}))
	fmt.Println("token in a cookie:", call(func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "auth_token", Value: token}) }))
	fmt.Println("bad token:", call(func(r *http.Request) { r.Header.Set("Authorization", "Bearer not-a-token") }))

	// Output:
	// bearer token: 200
	// no token: 401
	// token in a cookie: 401
	// bad token: 401
}

// ExampleAddValidatorCheck reports the identity provider behind a service's
// token validators as a readiness check. The check is degraded, not failing, so
// an identity provider outage shows in the report without taking the service out
// of rotation.
//
// The example serves a minimal discovery document and key set so that it runs
// without a real provider.
func ExampleAddValidatorCheck() {
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuer.URL, issuer.URL+"/jwks")
		case "/jwks":
			_, _ = fmt.Fprint(w, `{"keys":[{"kty":"RSA","kid":"k1"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuer.Close()

	readiness := lifecycle.NewReadiness()
	server.AddValidatorCheck(readiness, []oidc.ValidatorConfig{{Issuer: issuer.URL}})
	readiness.MarkStarted()

	report, err := readiness.Ready(context.Background())
	fmt.Println(err)
	fmt.Println(report)
	// Output:
	// <nil>
	// map[jwt-validators:ok]
}

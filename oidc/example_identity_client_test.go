package oidc_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"

	"github.com/dioad/net/tls"
	"github.com/dioad/util"

	"github.com/dioad/auth/oidc"
)

// ExampleNewIdentityClient builds the HTTP client one service uses to call
// another. With an identity it authenticates as that identity, here with the
// OAuth2 client credentials grant. With the zero identity it is a plain
// client, which suits local development against a service without auth.
//
// The helpers below stand in for the identity provider and the service being
// called.
func ExampleNewIdentityClient() {
	service := newEchoAuthService(httptest.NewServer)
	defer service.Close()

	provider := newTokenProvider(httptest.NewServer)
	defer provider.server.Close()

	ctx := context.Background()

	plain, err := oidc.NewIdentityClient(ctx, oidc.ClientConfig{}, tls.ClientConfig{})
	if err != nil {
		fmt.Println(err)
		return
	}
	_, header, _ := get(ctx, plain, service.URL)
	fmt.Printf("plain client sends: %q\n", header)

	// provider.identity() is an oidc.ClientConfig with the provider's URL, a
	// client ID and a client secret.
	authenticated, err := oidc.NewIdentityClient(ctx, provider.identity(), tls.ClientConfig{})
	if err != nil {
		fmt.Println(err)
		return
	}
	_, header, _ = get(ctx, authenticated, service.URL)
	fmt.Printf("identity client sends: %q\n", header)

	// Output:
	// plain client sends: ""
	// identity client sends: "Bearer service-token"
}

// tokenProvider is an identity provider that issues "service-token" for the
// client credentials grant and counts how many tokens it has issued.
type tokenProvider struct {
	server *httptest.Server
	issued atomic.Int32
}

// newTokenProvider starts a tokenProvider using newServer, which is
// httptest.NewServer or httptest.NewTLSServer.
func newTokenProvider(newServer func(http.Handler) *httptest.Server) *tokenProvider {
	p := &tokenProvider{}
	mux := http.NewServeMux()
	p.server = newServer(mux)

	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":         p.server.URL,
			"token_endpoint": p.server.URL + "/token",
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("grant_type") != "client_credentials" || r.PostFormValue("client_secret") != "service-secret" {
			http.Error(w, "invalid_client", http.StatusUnauthorized)
			return
		}
		p.issued.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "service-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	return p
}

func (p *tokenProvider) identity() oidc.ClientConfig {
	return oidc.ClientConfig{
		URL:          p.server.URL,
		ClientID:     "billing-service",
		ClientSecret: *util.NewMaskedString("service-secret"),
	}
}

// newEchoAuthService starts a service that replies with the Authorization
// header it was sent.
func newEchoAuthService(newServer func(http.Handler) *httptest.Server) *httptest.Server {
	return newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, r.Header.Get("Authorization"))
	}))
}

// get returns the status and body of a GET to url, or the request error.
func get(ctx context.Context, client *http.Client, url string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	var body [256]byte
	n, _ := resp.Body.Read(body[:])
	return resp.StatusCode, string(body[:n]), nil
}

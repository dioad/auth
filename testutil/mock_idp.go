package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gopkg.in/go-jose/go-jose.v2"
)

// MockIdP is a mock Identity Provider for testing OIDC flows.
type MockIdP struct {
	Server *httptest.Server
	Key    *rsa.PrivateKey
	Issuer string
}

// NewMockIdP creates a new MockIdP.
func NewMockIdP() (*MockIdP, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	idp := &MockIdP{
		Key: key,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", idp.handleDiscovery)
	mux.HandleFunc("/jwks.json", idp.handleJWKS)
	mux.HandleFunc("/authorize", idp.handleAuthorize)
	mux.HandleFunc("/token", idp.handleToken)
	mux.HandleFunc("/userinfo", idp.handleUserInfo)

	idp.Server = httptest.NewServer(mux)
	idp.Issuer = idp.Server.URL

	return idp, nil
}

// Close stops the mock IDP server.
func (i *MockIdP) Close() {
	i.Server.Close()
}

func (i *MockIdP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	config := map[string]any{
		"issuer":                                i.Issuer,
		"authorization_endpoint":                i.Issuer + "/authorize",
		"token_endpoint":                        i.Issuer + "/token",
		"userinfo_endpoint":                     i.Issuer + "/userinfo",
		"jwks_uri":                              i.Issuer + "/jwks.json",
		"response_types_supported":              []string{"code", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email"},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (i *MockIdP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       &i.Key.PublicKey,
		KeyID:     "test-key",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	resp := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		_ = fmt.Errorf("failed to encode JWKS: %w", err)
	}
}

func (i *MockIdP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	code := uuid.New().String()

	http.Redirect(w, r, fmt.Sprintf("%s?code=%s&state=%s", redirectURI, code, state), http.StatusFound)
}

func (i *MockIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   i.Issuer,
		"sub":   "test-user",
		"aud":   "test-client",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"email": "test@example.com",
	})
	token.Header["kid"] = "test-key"

	tokenString, _ := token.SignedString(i.Key)

	resp := map[string]any{
		"access_token": tokenString,
		"id_token":     tokenString,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (i *MockIdP) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	user := map[string]any{
		"sub":   "test-user",
		"email": "test@example.com",
		"name":  "Test User",
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

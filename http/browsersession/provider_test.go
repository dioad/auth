package browsersession_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/oidc"
)

// fakeProvider is an identity provider with discovery, authorization, token
// and end-session endpoints. It issues "access-1" and "refresh-1" for the
// authorization code grant and "access-2" and "refresh-2" for a refresh.
type fakeProvider struct {
	Server *httptest.Server

	mu             sync.Mutex
	endedSessions  []string
	refreshStatus  int
	codeExchanges  int
	refreshedWith  []string
	endSessionCode int
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()

	p := &fakeProvider{refreshStatus: http.StatusOK, endSessionCode: http.StatusNoContent}
	mux := http.NewServeMux()
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Server.Close)

	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 p.Server.URL,
			"authorization_endpoint": p.Server.URL + "/authorize",
			"token_endpoint":         p.Server.URL + "/token",
			"end_session_endpoint":   p.Server.URL + "/logout",
		})
	})
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.endedSessions = append(p.endedSessions, r.PostFormValue("refresh_token"))
		status := p.endSessionCode
		p.mu.Unlock()
		w.WriteHeader(status)
	})
	return p
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func (p *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

	resp := tokenResponse{TokenType: "Bearer", ExpiresIn: 3600}
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		p.codeExchanges++
		resp.AccessToken, resp.RefreshToken = "access-1", "refresh-1"
	case "refresh_token":
		p.refreshedWith = append(p.refreshedWith, r.PostFormValue("refresh_token"))
		if p.refreshStatus != http.StatusOK {
			http.Error(w, "invalid_grant", p.refreshStatus)
			return
		}
		resp.AccessToken, resp.RefreshToken = "access-2", "refresh-2"
	default:
		http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (p *fakeProvider) client(t *testing.T) *oidc.Client {
	t.Helper()

	endpoint, err := oidc.NewEndpoint(p.Server.URL)
	require.NoError(t, err)
	return oidc.NewClient(endpoint, oidc.WithClientIDAndSecret("console", "console-secret"))
}

func (p *fakeProvider) ended() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.endedSessions...)
}

// queryOf returns the query parameters of a redirect Location header.
func queryOf(t *testing.T, location string) url.Values {
	t.Helper()

	u, err := url.Parse(location)
	require.NoError(t, err)
	return u.Query()
}

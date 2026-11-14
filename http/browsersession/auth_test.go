package browsersession_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/http/browsersession"
	oidcmw "github.com/dioad/auth/http/middleware/oidc"
)

const (
	testRedirectURI = "https://console.example/app/auth/callback"
	testLoginPath   = "/app/auth/login"
)

func newTestAuthHandler(t *testing.T, provider *fakeProvider) (*browsersession.AuthHandler, *browsersession.CookieSet) {
	t.Helper()

	cookies := newTestCookieSet(t)
	client := provider.client(t)
	oidcHandler := oidcmw.NewHandler(client, oidcmw.OIDCConfig{
		Scopes:      []string{"openid"},
		RedirectURI: testRedirectURI,
		LoginPath:   testLoginPath,
	})
	return &browsersession.AuthHandler{
		OIDCHandler:    oidcHandler,
		OIDCClient:     client,
		RedirectURI:    testRedirectURI,
		PostLoginPath:  "/app/ui/",
		PostLogoutPath: "/app/ui/",
		Cookies:        cookies,
		PublicConfig:   browsersession.PublicConfig{Issuer: provider.Server.URL, ClientID: "console"},
	}, cookies
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// loginState starts a login and returns the state the provider is sent and
// the state cookie the browser is given.
func loginState(t *testing.T, h http.Handler) (string, *http.Cookie) {
	t.Helper()

	rr := serve(h, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil))
	require.Equal(t, http.StatusFound, rr.Code)

	state := queryOf(t, rr.Header().Get("Location")).Get("state")
	require.NotEmpty(t, state)

	for _, c := range rr.Result().Cookies() {
		if c.Name == oidcmw.DefaultStateCookieName {
			return state, c
		}
	}
	require.FailNow(t, "login did not set a state cookie")
	return "", nil
}

func TestAuthHandler_Login(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	auth, _ := newTestAuthHandler(t, provider)

	rr := serve(auth.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil))

	require.Equal(t, http.StatusFound, rr.Code)
	location := rr.Header().Get("Location")
	assert.Contains(t, location, provider.Server.URL+"/authorize")
	assert.Equal(t, testRedirectURI, queryOf(t, location).Get("redirect_uri"))
}

func TestAuthHandler_Callback_SetsSession(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	auth, cookies := newTestAuthHandler(t, provider)
	state, stateCookie := loginState(t, auth.Handler())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback?code=abc&state="+state, nil)
	req.AddCookie(stateCookie)
	rr := serve(auth.Handler(), req)

	require.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/app/ui/", rr.Header().Get("Location"))
	assert.Contains(t, expiredCookies(rr), oidcmw.DefaultStateCookieName, "the state cookie is single use")

	session, ok := sessionFromResponse(t, cookies, rr)
	require.True(t, ok)
	assert.Equal(t, "access-1", session.AccessToken)
	assert.Equal(t, "refresh-1", session.RefreshToken)
	assert.False(t, session.Expiry.IsZero())
}

func TestAuthHandler_Callback_Rejects(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	auth, cookies := newTestAuthHandler(t, provider)
	state, stateCookie := loginState(t, auth.Handler())

	tests := []struct {
		name        string
		query       string
		stateCookie *http.Cookie
	}{
		{name: "provider error", query: "error=access_denied&error_description=nope", stateCookie: stateCookie},
		{name: "missing code", query: "state=" + state, stateCookie: stateCookie},
		{name: "missing state", query: "code=abc", stateCookie: stateCookie},
		{name: "state cookie expired", query: "code=abc&state=" + state},
		{name: "state mismatch", query: "code=abc&state=other", stateCookie: stateCookie},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback?"+tt.query, nil)
			if tt.stateCookie != nil {
				req.AddCookie(tt.stateCookie)
			}
			rr := serve(auth.Handler(), req)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			_, ok := sessionFromResponse(t, cookies, rr)
			assert.False(t, ok, "a rejected callback must not start a session")
		})
	}
}

func TestAuthHandler_Logout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		providerStatus int
	}{
		{name: "provider ends the session", providerStatus: http.StatusNoContent},
		// The console's own sign-out must not depend on the provider.
		{name: "provider refuses", providerStatus: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := newFakeProvider(t)
			provider.endSessionCode = tt.providerStatus
			auth, cookies := newTestAuthHandler(t, provider)

			req := requestWithSession(t, cookies, http.MethodPost, "/logout", browsersession.Session{
				AccessToken: "access", RefreshToken: "refresh", Expiry: inOneHour(),
			})
			rr := serve(auth.Handler(), req)

			assert.Equal(t, http.StatusFound, rr.Code)
			assert.Equal(t, "/app/ui/", rr.Header().Get("Location"))
			assert.Equal(t, []string{"refresh"}, provider.ended(), "the provider must be asked to end the session")
			assert.ElementsMatch(t, sessionCookieNames, expiredCookies(rr))
		})
	}
}

// TestAuthHandler_Logout_WithoutSession covers a cross-site logout: the
// browser withholds the SameSite=Lax cookies, so there must be nothing to
// clear and nobody's provider session to end.
func TestAuthHandler_Logout_WithoutSession(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	auth, _ := newTestAuthHandler(t, provider)

	rr := serve(auth.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/logout", nil))

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Empty(t, provider.ended())
	assert.Empty(t, expiredCookies(rr))
}

func TestAuthHandler_Logout_RejectsGET(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	auth, cookies := newTestAuthHandler(t, provider)

	req := requestWithSession(t, cookies, http.MethodGet, "/logout", browsersession.Session{AccessToken: "access"})
	rr := serve(auth.Handler(), req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code, "a link or image must not be able to sign a user out")
	assert.Empty(t, expiredCookies(rr))
}

func TestAuthHandler_Config(t *testing.T) {
	t.Parallel()

	provider := newFakeProvider(t)
	auth, _ := newTestAuthHandler(t, provider)

	rr := serve(auth.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/config", nil))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"client_id":"console"`)
	assert.Contains(t, rr.Body.String(), `"issuer":"`+provider.Server.URL+`"`)
}

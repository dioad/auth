package browsersession_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/http/browsersession"
	oidcmw "github.com/dioad/auth/http/middleware/oidc"
)

func TestNewCookieSet_Validation(t *testing.T) {
	t.Parallel()

	named := func(name string) oidcmw.CookieConfig { return oidcmw.CookieConfig{Name: name} }

	tests := []struct {
		name                   string
		key                    string
		token, refresh, expiry oidcmw.CookieConfig
		wantErr                bool
	}{
		{name: "valid", key: testKey, token: named("a"), refresh: named("b"), expiry: named("c")},
		{name: "short key", key: "0f0f", token: named("a"), refresh: named("b"), expiry: named("c"), wantErr: true},
		{name: "unnamed cookie", key: testKey, token: named("a"), refresh: named(""), expiry: named("c"), wantErr: true},
		{name: "duplicate names", key: testKey, token: named("a"), refresh: named("b"), expiry: named("a"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := browsersession.NewCookieSet(tt.key, tt.token, tt.refresh, tt.expiry)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestDefaultCookieNames_NotReadByJWTMiddleware pins the session cookie names
// away from the names this module's bearer-token middleware has read, so a
// session cookie is never offered to a JWT validator.
func TestDefaultCookieNames_NotReadByJWTMiddleware(t *testing.T) {
	t.Parallel()

	for _, name := range sessionCookieNames {
		assert.NotEqual(t, "auth_token", name)
		assert.NotEqual(t, oidcmw.DefaultTokenCookieName, name)
	}
}

func TestCookieSet_SetGet(t *testing.T) {
	t.Parallel()

	expiry := inOneHour()

	tests := []struct {
		name        string
		session     browsersession.Session
		wantCookies []string
	}{
		{
			name:        "full session",
			session:     browsersession.Session{AccessToken: "access", RefreshToken: "refresh", Expiry: expiry},
			wantCookies: sessionCookieNames,
		},
		{
			name:        "access token only",
			session:     browsersession.Session{AccessToken: "access"},
			wantCookies: []string{browsersession.DefaultTokenCookieName},
		},
		{
			// A JWT is base64url, but an opaque token may hold anything.
			name:        "token with reserved characters",
			session:     browsersession.Session{AccessToken: "a+b/c=d; e,f\"g", RefreshToken: "r+/="},
			wantCookies: []string{browsersession.DefaultTokenCookieName, browsersession.DefaultRefreshCookieName},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cookies := newTestCookieSet(t)
			rr := httptest.NewRecorder()
			require.NoError(t, cookies.Set(rr, tt.session))

			result := rr.Result().Cookies()
			names := make([]string, 0, len(result))
			for _, c := range result {
				names = append(names, c.Name)
				assert.True(t, c.HttpOnly, "%s must be HttpOnly", c.Name)
				assert.True(t, c.Secure, "%s must be Secure", c.Name)
				assert.Equal(t, http.SameSiteLaxMode, c.SameSite, "%s must be SameSite=Lax", c.Name)
				assert.NotContains(t, c.Value, "access", "%s must not carry a token in the clear", c.Name)
			}
			assert.ElementsMatch(t, tt.wantCookies, names)

			got, ok := sessionFromResponse(t, cookies, rr)
			require.True(t, ok)
			assert.Equal(t, tt.session, got)
		})
	}
}

func TestCookieSet_Set_RequiresAccessToken(t *testing.T) {
	t.Parallel()

	rr := httptest.NewRecorder()
	err := newTestCookieSet(t).Set(rr, browsersession.Session{RefreshToken: "refresh"})
	require.Error(t, err)
	assert.Empty(t, rr.Result().Cookies(), "nothing must be written for an invalid session")
}

func TestCookieSet_Get_Rejects(t *testing.T) {
	t.Parallel()

	cookies := newTestCookieSet(t)
	session := browsersession.Session{AccessToken: "access", RefreshToken: "refresh", Expiry: inOneHour()}

	otherKey, err := browsersession.NewCookieSet(strings.Repeat("aa", 32), cookies.Token, cookies.Refresh, cookies.Expiry)
	require.NoError(t, err)

	tests := []struct {
		name    string
		request func(t *testing.T) *http.Request
	}{
		{
			name: "no cookies",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				return httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			},
		},
		{
			name: "encrypted with another key",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				return requestWithSession(t, otherKey, http.MethodGet, "/", session)
			},
		},
		{
			name: "a bearer token in place of ciphertext",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{Name: browsersession.DefaultTokenCookieName, Value: "eyJhbGciOiJIUzI1NiJ9.e30.c2ln"})
				return req
			},
		},
		{
			// The refresh token must not be accepted as an access token.
			name: "refresh cookie value moved into the token cookie",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				signedIn := requestWithSession(t, cookies, http.MethodGet, "/", session)
				refresh, err := signedIn.Cookie(browsersession.DefaultRefreshCookieName)
				require.NoError(t, err)

				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{Name: browsersession.DefaultTokenCookieName, Value: refresh.Value})
				return req
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := cookies.Get(tt.request(t))
			require.Error(t, err)
			assert.Equal(t, browsersession.Session{}, got)
		})
	}
}

// TestCookieSet_Get_OptionalCookiesUnreadable covers a session whose refresh
// or expiry cookie cannot be read: it is still a session, just one that is
// never refreshed.
func TestCookieSet_Get_OptionalCookiesUnreadable(t *testing.T) {
	t.Parallel()

	cookies := newTestCookieSet(t)
	signedIn := requestWithSession(t, cookies, http.MethodGet, "/", browsersession.Session{
		AccessToken: "access", RefreshToken: "refresh", Expiry: inOneHour(),
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	for _, c := range signedIn.Cookies() {
		if c.Name != browsersession.DefaultTokenCookieName {
			c.Value = "garbage"
		}
		req.AddCookie(c)
	}

	got, err := cookies.Get(req)
	require.NoError(t, err)
	assert.Equal(t, browsersession.Session{AccessToken: "access"}, got)
}

func TestCookieSet_Clear(t *testing.T) {
	t.Parallel()

	rr := httptest.NewRecorder()
	newTestCookieSet(t).Clear(rr)

	assert.ElementsMatch(t, sessionCookieNames, expiredCookies(rr))
}

func TestSession_ExpiresWithin(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		session browsersession.Session
		want    bool
	}{
		{name: "inside the window", session: browsersession.Session{RefreshToken: "r", Expiry: now.Add(2 * time.Minute)}, want: true},
		{name: "already expired", session: browsersession.Session{RefreshToken: "r", Expiry: now.Add(-time.Minute)}, want: true},
		{name: "outside the window", session: browsersession.Session{RefreshToken: "r", Expiry: now.Add(time.Hour)}},
		{name: "unknown expiry", session: browsersession.Session{RefreshToken: "r"}},
		{name: "no refresh token", session: browsersession.Session{Expiry: now.Add(2 * time.Minute)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, tt.session.ExpiresWithin(5*time.Minute, now))
		})
	}
}

package browsersession_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/dioad/auth/http/browsersession"
)

const refreshWindow = 5 * time.Minute

// authHeaderRecorder is a next handler that records the Authorization header
// it was served with.
type authHeaderRecorder struct {
	called bool
	header string
}

func (h *authHeaderRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.header = r.Header.Get("Authorization")
	w.WriteHeader(http.StatusOK)
}

func refreshTo(token *oauth2.Token, err error, calls *[]string) browsersession.RefreshFunc {
	return func(_ context.Context, refreshToken string) (*oauth2.Token, error) {
		*calls = append(*calls, refreshToken)
		return token, err
	}
}

func TestCookieAuthMiddleware(t *testing.T) {
	t.Parallel()

	cookies := newTestCookieSet(t)
	session := browsersession.Session{AccessToken: "access", RefreshToken: "refresh", Expiry: inOneHour()}

	tests := []struct {
		name       string
		request    func(t *testing.T) *http.Request
		wantStatus int
		wantHeader string
	}{
		{
			name: "session cookie is promoted to a bearer token",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				return requestWithSession(t, cookies, http.MethodGet, "/", session)
			},
			wantStatus: http.StatusOK,
			wantHeader: "Bearer access",
		},
		{
			name: "no session",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				return httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			// The caller must not be able to pick which credential is checked.
			name: "authorization header alongside a session",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				req := requestWithSession(t, cookies, http.MethodGet, "/", session)
				req.Header.Set("Authorization", "Bearer attacker")
				return req
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "authorization header without a session",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer attacker")
				return req
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			next := &authHeaderRecorder{}
			rr := serve(browsersession.CookieAuthMiddleware(cookies)(next), tt.request(t))

			assert.Equal(t, tt.wantStatus, rr.Code)
			assert.Equal(t, tt.wantStatus == http.StatusOK, next.called)
			assert.Equal(t, tt.wantHeader, next.header)
		})
	}
}

func TestRefreshMiddleware(t *testing.T) {
	t.Parallel()

	cookies := newTestCookieSet(t)
	fresh := &oauth2.Token{AccessToken: "access-2", RefreshToken: "refresh-2", Expiry: inOneHour()}
	dueSession := browsersession.Session{AccessToken: "access-1", RefreshToken: "refresh-1", Expiry: time.Now().Add(time.Minute)}

	tests := []struct {
		name           string
		session        browsersession.Session
		token          *oauth2.Token
		refreshErr     error
		wantRefreshed  bool
		wantStatus     int
		wantHeader     string
		wantNewSession string
		wantCleared    bool
	}{
		{
			name:           "due: new cookies and new header",
			session:        dueSession,
			token:          fresh,
			wantRefreshed:  true,
			wantStatus:     http.StatusOK,
			wantHeader:     "Bearer access-2",
			wantNewSession: "access-2",
		},
		{
			name:        "due: refresh fails, session cleared",
			session:     dueSession,
			refreshErr:  errors.New("invalid_grant"),
			wantStatus:  http.StatusUnauthorized,
			wantCleared: true,
			// The refresh was attempted, so the call is recorded below.
			wantRefreshed: true,
		},
		{
			name:          "due: refresh returns no access token",
			session:       dueSession,
			token:         &oauth2.Token{},
			wantRefreshed: true,
			wantStatus:    http.StatusUnauthorized,
			wantCleared:   true,
		},
		{
			name:       "not due",
			session:    browsersession.Session{AccessToken: "access-1", RefreshToken: "refresh-1", Expiry: inOneHour()},
			wantStatus: http.StatusOK,
			wantHeader: "Bearer access-1",
		},
		{
			name:       "no refresh token",
			session:    browsersession.Session{AccessToken: "access-1", Expiry: time.Now().Add(time.Minute)},
			wantStatus: http.StatusOK,
			wantHeader: "Bearer access-1",
		},
		{
			name:       "unknown expiry",
			session:    browsersession.Session{AccessToken: "access-1", RefreshToken: "refresh-1"},
			wantStatus: http.StatusOK,
			wantHeader: "Bearer access-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var calls []string
			next := &authHeaderRecorder{}
			mw := browsersession.RefreshMiddleware(cookies, refreshWindow, refreshTo(tt.token, tt.refreshErr, &calls))

			rr := serve(mw(next), requestWithSession(t, cookies, http.MethodGet, "/", tt.session))

			assert.Equal(t, tt.wantStatus, rr.Code)
			assert.Equal(t, tt.wantStatus == http.StatusOK, next.called)
			assert.Equal(t, tt.wantHeader, next.header)
			if tt.wantRefreshed {
				assert.Equal(t, []string{tt.session.RefreshToken}, calls)
			} else {
				assert.Empty(t, calls, "a session that is not due must not be refreshed")
			}
			if tt.wantCleared {
				assert.ElementsMatch(t, sessionCookieNames, expiredCookies(rr))
			}
			if tt.wantNewSession != "" {
				got, ok := sessionFromResponse(t, cookies, rr)
				require.True(t, ok)
				assert.Equal(t, tt.wantNewSession, got.AccessToken)
				assert.Equal(t, "refresh-2", got.RefreshToken)
			}
		})
	}
}

func TestRefreshMiddleware_NoSession(t *testing.T) {
	t.Parallel()

	cookies := newTestCookieSet(t)
	next := &authHeaderRecorder{}
	mw := browsersession.RefreshMiddleware(cookies, refreshWindow, nil)

	rr := serve(mw(next), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.False(t, next.called)
}

func TestSessionGuard(t *testing.T) {
	t.Parallel()

	cookies := newTestCookieSet(t)
	fresh := &oauth2.Token{AccessToken: "access-2", RefreshToken: "refresh-2", Expiry: inOneHour()}
	dueSession := browsersession.Session{AccessToken: "access-1", RefreshToken: "refresh-1", Expiry: time.Now().Add(time.Minute)}

	tests := []struct {
		name       string
		request    func(t *testing.T) *http.Request
		refreshErr error
		wantStatus int
		wantCalled bool
		wantNew    string
	}{
		{
			name: "session passes",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				return requestWithSession(t, cookies, http.MethodGet, "/", browsersession.Session{AccessToken: "access-1", Expiry: inOneHour()})
			},
			wantStatus: http.StatusOK,
			wantCalled: true,
		},
		{
			name: "no session redirects to login",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				return httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/deep/link", nil)
			},
			wantStatus: http.StatusSeeOther,
		},
		{
			name: "due session is refreshed",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				return requestWithSession(t, cookies, http.MethodGet, "/", dueSession)
			},
			wantStatus: http.StatusOK,
			wantCalled: true,
			wantNew:    "access-2",
		},
		{
			name: "failed refresh redirects to login",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				return requestWithSession(t, cookies, http.MethodGet, "/", dueSession)
			},
			refreshErr: errors.New("invalid_grant"),
			wantStatus: http.StatusSeeOther,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var calls []string
			next := &authHeaderRecorder{}
			guard := browsersession.SessionGuard(cookies, "/app/auth/login", refreshWindow, refreshTo(fresh, tt.refreshErr, &calls))

			rr := serve(guard(next), tt.request(t))

			assert.Equal(t, tt.wantStatus, rr.Code)
			assert.Equal(t, tt.wantCalled, next.called)
			if tt.wantStatus == http.StatusSeeOther {
				assert.Equal(t, "/app/auth/login", rr.Header().Get("Location"))
			}
			if tt.wantNew != "" {
				got, ok := sessionFromResponse(t, cookies, rr)
				require.True(t, ok)
				assert.Equal(t, tt.wantNew, got.AccessToken)
			}
		})
	}
}

func TestSPAHandler(t *testing.T) {
	t.Parallel()

	staticFS := fstest.MapFS{
		"index.html":    {Data: []byte("<html>app</html>")},
		"assets/app.js": {Data: []byte("console.log('app')")},
	}
	handler := browsersession.SPAHandler(staticFS)

	tests := []struct {
		name     string
		path     string
		wantBody string
	}{
		{name: "root", path: "/", wantBody: "<html>app</html>"},
		{name: "a file", path: "/assets/app.js", wantBody: "console.log('app')"},
		{name: "a client-side route", path: "/accounts/42/usage", wantBody: "<html>app</html>"},
		{name: "a missing file", path: "/assets/missing.js", wantBody: "<html>app</html>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rr := serve(handler, httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, nil))

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, tt.wantBody, rr.Body.String())
		})
	}
}

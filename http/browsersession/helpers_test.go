package browsersession_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/http/browsersession"
	oidcmw "github.com/dioad/auth/http/middleware/oidc"
)

// testKey is a cookie encryption key: 64 hexadecimal characters.
var testKey = strings.Repeat("0f", 32)

func newTestCookieSet(t *testing.T) *browsersession.CookieSet {
	t.Helper()

	cookies, err := browsersession.NewCookieSet(testKey,
		oidcmw.CookieConfig{Name: browsersession.DefaultTokenCookieName, Path: "/", Secure: true},
		oidcmw.CookieConfig{Name: browsersession.DefaultRefreshCookieName, Path: "/", Secure: true},
		oidcmw.CookieConfig{Name: browsersession.DefaultExpiryCookieName, Path: "/", Secure: true},
	)
	require.NoError(t, err)
	return cookies
}

// requestWithSession returns a request carrying session in its cookies.
func requestWithSession(t *testing.T, cookies *browsersession.CookieSet, method, target string, session browsersession.Session) *http.Request {
	t.Helper()

	rr := httptest.NewRecorder()
	require.NoError(t, cookies.Set(rr, session))

	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// sessionFromResponse returns the session that rr's Set-Cookie headers leave
// in the browser, and whether there is one.
func sessionFromResponse(t *testing.T, cookies *browsersession.CookieSet, rr *httptest.ResponseRecorder) (browsersession.Session, bool) {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge >= 0 {
			req.AddCookie(c)
		}
	}
	session, err := cookies.Get(req)
	return session, err == nil
}

// expiredCookies returns the names of the cookies the response expires.
func expiredCookies(rr *httptest.ResponseRecorder) []string {
	var names []string
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge < 0 {
			names = append(names, c.Name)
		}
	}
	return names
}

var sessionCookieNames = []string{
	browsersession.DefaultTokenCookieName,
	browsersession.DefaultRefreshCookieName,
	browsersession.DefaultExpiryCookieName,
}

func inOneHour() time.Time {
	return time.Now().Add(time.Hour).UTC().Truncate(time.Second)
}

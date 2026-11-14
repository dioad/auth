package browsersession_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/dioad/auth/http/browsersession"
	oidcmw "github.com/dioad/auth/http/middleware/oidc"
)

// ExampleCookieSet sets a session, reads it back from the request a browser
// would send, and clears it.
func ExampleCookieSet() {
	// The key is 64 hexadecimal characters. Generate one with
	// "openssl rand -hex 32" and keep it out of source control.
	key := strings.Repeat("0f", 32)

	cookies, err := browsersession.NewCookieSet(key,
		oidcmw.CookieConfig{Name: "bff_session", Path: "/", Secure: true},
		oidcmw.CookieConfig{Name: "bff_refresh", Path: "/", Secure: true},
		oidcmw.CookieConfig{Name: "bff_expiry", Path: "/", Secure: true},
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Set: the response carries one encrypted cookie per part of the session.
	response := httptest.NewRecorder()
	err = cookies.Set(response, browsersession.Session{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		Expiry:       time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range response.Result().Cookies() {
		fmt.Println("set:", c.Name, "httponly:", c.HttpOnly, "plaintext:", strings.Contains(c.Value, "access-token"))
		request.AddCookie(c)
	}

	// Get: the server decrypts the cookies the browser sends back.
	session, err := cookies.Get(request)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("get:", session.AccessToken, session.RefreshToken, session.Expiry.Format(time.RFC3339))

	// Clear: every cookie is expired.
	cleared := httptest.NewRecorder()
	cookies.Clear(cleared)
	for _, c := range cleared.Result().Cookies() {
		fmt.Println("clear:", c.Name, "max-age:", c.MaxAge)
	}

	// Output:
	// set: bff_session httponly: true plaintext: false
	// set: bff_refresh httponly: true plaintext: false
	// set: bff_expiry httponly: true plaintext: false
	// get: access-token refresh-token 2030-01-01T12:00:00Z
	// clear: bff_session max-age: -1
	// clear: bff_refresh max-age: -1
	// clear: bff_expiry max-age: -1
}

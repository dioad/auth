package browsersession_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing/fstest"

	"github.com/dioad/auth/http/browsersession"
	oidcmw "github.com/dioad/auth/http/middleware/oidc"
	"github.com/dioad/auth/testutil"
)

// ExampleNewApp protects a single-page app and its API with a browser session.
// A real deployment mounts App.Auth, App.UI and App.API under path prefixes
// of one server. The example mounts them on one mux, signs in against a mock
// identity provider and calls the API with the session cookies.
func ExampleNewApp() {
	idp, err := testutil.NewMockIDP()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer idp.Close()

	// The API behind the session sees an ordinary bearer token. A real API
	// validates it, for example with server.OAuth2ValidatorHandler.
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "bearer token present:", strings.HasPrefix(r.Header.Get("Authorization"), "Bearer "))
	})
	staticFS := fstest.MapFS{"index.html": {Data: []byte("<html>console</html>")}}

	app, err := browsersession.NewApp(browsersession.Config{
		OIDC: oidcmw.BrowserConfig{
			Issuer:       idp.Issuer,
			ClientID:     "console",
			ClientSecret: "console-secret",
			RedirectURI:  "https://console.example/auth/callback",
			LoginPath:    "/auth/login",
			CookieSecure: true,
		},
		CookieEncryptionKey: strings.Repeat("0f", 32),
		PostLoginPath:       "/",
	}, api, staticFS)
	if err != nil {
		fmt.Println(err)
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", app.Auth))
	mux.Handle("/api/", http.StripPrefix("/api", app.API))
	mux.Handle("/", app.UI)

	do := func(method, target string, cookies []*http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}

	// Without a session the page redirects to login and the API says 401.
	fmt.Println("page:", do(http.MethodGet, "/", nil).Header().Get("Location"))
	fmt.Println("api:", do(http.MethodGet, "/api/me", nil).Code)

	// Login redirects to the provider and sets a state cookie.
	login := do(http.MethodGet, "/auth/login", nil)
	state := ""
	if u, err := url.Parse(login.Header().Get("Location")); err == nil {
		state = u.Query().Get("state")
	}

	// The provider sends the browser back with a code. The callback checks
	// the state, exchanges the code and sets the session cookies.
	callback := do(http.MethodGet, "/auth/callback?code=abc&state="+state, login.Result().Cookies())
	fmt.Println("callback:", callback.Code, callback.Header().Get("Location"))

	var session []*http.Cookie
	for _, c := range callback.Result().Cookies() {
		if c.MaxAge >= 0 {
			session = append(session, c)
		}
	}

	// With the session the page is served and the API sees a bearer token.
	fmt.Println("page:", do(http.MethodGet, "/", session).Body.String())
	fmt.Print("api: ", do(http.MethodGet, "/api/me", session).Body.String())

	// Output:
	// page: /auth/login
	// api: 401
	// callback: 302 /
	// page: <html>console</html>
	// api: bearer token present: true
}

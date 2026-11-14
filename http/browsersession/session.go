// Package browsersession protects a browser UI with an OIDC login and a
// backend-for-frontend (BFF) session.
//
// The browser never holds a usable token. After login the access token, the
// refresh token and the access token's expiry are each stored in their own
// AES-GCM encrypted, HttpOnly, SameSite=Lax cookie. On every API request the
// server decrypts the access token and promotes it to an Authorization
// header, so the API behind it validates a bearer token exactly as it does
// for a machine caller. A token close to expiry is refreshed on the way
// through.
//
// NewApp wires the pieces together. They are also exported for services that
// need a different arrangement:
//
//   - CookieSet reads, writes and clears the encrypted session cookies.
//   - AuthHandler serves login, the OIDC callback, logout and a public
//     config document.
//   - CookieAuthMiddleware promotes the session cookie to an Authorization
//     header, and RefreshMiddleware refreshes a token that is about to expire.
//   - SPAHandler serves a single-page app, and SessionGuard redirects a
//     browser without a session to login.
//
// # Cookies and CSRF
//
// The session cookies are SameSite=Lax, so a browser does not attach them to
// a cross-site POST, PUT, PATCH or DELETE. State-changing API routes must
// therefore not be reachable by GET. Logout is POST only and does nothing
// without a session cookie, so another site cannot sign a user out.
//
// The session cookie is not a bearer token: its value is ciphertext, and its
// default name is not one a JWT middleware reads. A machine API on the same
// origin should accept the Authorization header only, which is the default
// for server.OAuth2ValidatorHandler.
package browsersession

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	oidcmw "github.com/dioad/auth/http/middleware/oidc"
)

// Default session cookie names. They are deliberately different from the
// cookie names read by this module's other middleware ("auth_token" and
// oidc.DefaultTokenCookieName), so a session cookie is never mistaken for a
// bearer token.
const (
	// DefaultTokenCookieName is the name of the encrypted access-token cookie.
	DefaultTokenCookieName = "bff_session"
	// DefaultRefreshCookieName is the name of the encrypted refresh-token cookie.
	DefaultRefreshCookieName = "bff_refresh"
	// DefaultExpiryCookieName is the name of the encrypted token-expiry cookie.
	DefaultExpiryCookieName = "bff_expiry"
)

// Session is the content of a browser session.
type Session struct {
	// AccessToken is the OAuth2 access token. It is always set.
	AccessToken string
	// RefreshToken is empty when the provider did not issue one, for example
	// without the offline_access scope. Such a session cannot be refreshed.
	RefreshToken string
	// Expiry is when AccessToken expires. It is zero when the provider did
	// not say, in which case the session is never refreshed proactively.
	Expiry time.Time
}

// ExpiresWithin reports whether the session can be refreshed and expires
// within window of now.
func (s Session) ExpiresWithin(window time.Duration, now time.Time) bool {
	if s.RefreshToken == "" || s.Expiry.IsZero() {
		return false
	}
	return s.Expiry.Sub(now) <= window
}

// CookieSet reads and writes a Session as three encrypted cookies. Keeping
// them in one set applies the Secure, Domain and Path attributes consistently
// when setting and deleting them.
type CookieSet struct {
	// Token configures the access-token cookie.
	Token oidcmw.CookieConfig
	// Refresh configures the refresh-token cookie.
	Refresh oidcmw.CookieConfig
	// Expiry configures the token-expiry cookie.
	Expiry oidcmw.CookieConfig

	key []byte
}

// NewCookieSet returns a CookieSet that encrypts with encryptionKey, which is
// 64 hexadecimal characters (an AES-256 key). The three cookies must have
// distinct, non-empty names.
func NewCookieSet(encryptionKey string, token, refresh, expiry oidcmw.CookieConfig) (*CookieSet, error) {
	key, err := parseKey(encryptionKey)
	if err != nil {
		return nil, err
	}
	if token.Name == "" || refresh.Name == "" || expiry.Name == "" {
		return nil, errors.New("session cookies must be named")
	}
	if token.Name == refresh.Name || token.Name == expiry.Name || refresh.Name == expiry.Name {
		return nil, errors.New("session cookies must have distinct names")
	}
	return &CookieSet{Token: token, Refresh: refresh, Expiry: expiry, key: key}, nil
}

// Set encrypts session and writes it to w. The refresh and expiry cookies are
// only written when session has a refresh token and a known expiry.
func (s *CookieSet) Set(w http.ResponseWriter, session Session) error {
	if session.AccessToken == "" {
		return errors.New("session has no access token")
	}

	// Encrypt everything before writing anything, so a failure does not
	// leave half a session in the response.
	type cookieValue struct {
		cookie oidcmw.CookieConfig
		value  string
	}
	values := []cookieValue{{cookie: s.Token, value: session.AccessToken}}
	if session.RefreshToken != "" {
		values = append(values, cookieValue{cookie: s.Refresh, value: session.RefreshToken})
	}
	if !session.Expiry.IsZero() {
		values = append(values, cookieValue{cookie: s.Expiry, value: session.Expiry.UTC().Format(time.RFC3339)})
	}

	cookies := make([]*http.Cookie, 0, len(values))
	for _, v := range values {
		encrypted, err := encrypt(s.key, []byte(v.value), v.cookie.Name)
		if err != nil {
			return fmt.Errorf("failed to encrypt %s cookie: %w", v.cookie.Name, err)
		}
		cookies = append(cookies, v.cookie.Cookie(encrypted))
	}
	for _, cookie := range cookies {
		http.SetCookie(w, cookie)
	}
	return nil
}

// Get decrypts the session carried by r. Only the access-token cookie is
// required: a missing or unreadable refresh-token or expiry cookie leaves
// that field of the Session zero.
func (s *CookieSet) Get(r *http.Request) (Session, error) {
	accessToken, err := s.read(r, s.Token.Name)
	if err != nil {
		return Session{}, err
	}
	session := Session{AccessToken: accessToken}

	if refreshToken, err := s.read(r, s.Refresh.Name); err == nil {
		session.RefreshToken = refreshToken
	}
	if expiry, err := s.read(r, s.Expiry.Name); err == nil {
		if t, err := time.Parse(time.RFC3339, expiry); err == nil {
			session.Expiry = t
		}
	}
	return session, nil
}

// Clear expires all three session cookies.
func (s *CookieSet) Clear(w http.ResponseWriter) {
	s.Token.Delete(w)
	s.Refresh.Delete(w)
	s.Expiry.Delete(w)
}

// Present reports whether r carries a session cookie, without decrypting it.
func (s *CookieSet) Present(r *http.Request) bool {
	_, err := r.Cookie(s.Token.Name)
	return err == nil
}

// read returns the decrypted value of the cookie called name.
func (s *CookieSet) read(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", fmt.Errorf("failed to get %s cookie: %w", name, err)
	}

	// CookieConfig.Cookie query-escapes the value it is given.
	value, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return "", fmt.Errorf("failed to unescape %s cookie: %w", name, err)
	}

	decrypted, err := decrypt(s.key, value, name)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt %s cookie: %w", name, err)
	}
	if len(decrypted) == 0 {
		return "", fmt.Errorf("%s cookie is empty", name)
	}
	return string(decrypted), nil
}

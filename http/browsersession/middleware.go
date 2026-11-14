package browsersession

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/dioad/net/http/json"
)

// RefreshFunc exchanges a refresh token for a new token. oidc.Client's
// RefreshToken method is one, once its options are bound.
type RefreshFunc func(ctx context.Context, refreshToken string) (*oauth2.Token, error)

// CookieAuthMiddleware promotes the session cookie to an Authorization:
// Bearer header, so that JWT validation further down the chain sees the
// session's access token. A request without a readable session is rejected
// with 401.
//
// A request that already carries an Authorization header is rejected with
// 400: on a browser-facing route the session cookie is the only accepted
// credential, and a caller must not be able to choose which one is checked.
func CookieAuthMiddleware(cookies *CookieSet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := json.NewResponseFromRequest(w, r)
			if r.Header.Get("Authorization") != "" {
				resp.BadRequest(json.LogErr(errors.New("authorization header not allowed for web session")))
				return
			}

			session, err := cookies.Get(r)
			if err != nil {
				resp.Unauthorized(json.LogErr(err), json.LogMessage("failed to get session cookie"))
				return
			}

			zerolog.Ctx(r.Context()).UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str("auth_source", "oidc_session")
			})

			r.Header.Set("Authorization", "Bearer "+session.AccessToken)
			next.ServeHTTP(w, r)
		})
	}
}

// RefreshMiddleware refreshes a session that expires within window. The new
// tokens are written back to the session cookies, and the Authorization
// header of the current request is updated so JWT validation sees the new
// access token. It runs after CookieAuthMiddleware.
//
// A session without a refresh token or a known expiry is passed through
// unchanged. When the refresh itself fails the session is cleared and the
// request is rejected with 401, so the browser app sends the user to login.
//
// Concurrent requests can each see an expiring token and each try to refresh
// it. With a provider that rotates refresh tokens the second attempt fails
// and ends the session. A per-session refresh lock would avoid that.
func RefreshMiddleware(cookies *CookieSet, window time.Duration, refresh RefreshFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := json.NewResponseFromRequest(w, r)
			session, err := cookies.Get(r)
			if err != nil {
				resp.Unauthorized(json.LogErr(err), json.LogMessage("failed to get session cookie"))
				return
			}

			session, err = refreshIfDue(w, r, cookies, session, window, refresh)
			if err != nil {
				cookies.Clear(w)
				resp.Unauthorized(json.LogErr(err), json.LogMessage("failed to refresh session"))
				return
			}

			r.Header.Set("Authorization", "Bearer "+session.AccessToken)
			next.ServeHTTP(w, r)
		})
	}
}

// SessionGuard redirects a browser without a readable session to loginPath,
// and refreshes a session that expires within window. It is for pages, where
// a redirect is the useful answer; API routes use CookieAuthMiddleware and
// RefreshMiddleware, which answer 401. A nil refresh disables refreshing.
func SessionGuard(cookies *CookieSet, loginPath string, window time.Duration, refresh RefreshFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := cookies.Get(r)
			if err != nil {
				http.Redirect(w, r, loginPath, http.StatusSeeOther)
				return
			}

			if _, err := refreshIfDue(w, r, cookies, session, window, refresh); err != nil {
				zerolog.Ctx(r.Context()).Error().Err(err).Msg("token refresh failed; clearing session and redirecting to login")
				cookies.Clear(w)
				http.Redirect(w, r, loginPath, http.StatusSeeOther)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// refreshIfDue returns session, refreshed first when it expires within
// window. The refreshed session is written to w. A failure to write it is
// logged, not returned: the new access token is still good for this request.
func refreshIfDue(w http.ResponseWriter, r *http.Request, cookies *CookieSet, session Session, window time.Duration, refresh RefreshFunc) (Session, error) {
	if refresh == nil || !session.ExpiresWithin(window, time.Now()) {
		return session, nil
	}

	token, err := refresh(r.Context(), session.RefreshToken)
	if err != nil {
		return Session{}, err
	}
	if token.AccessToken == "" {
		return Session{}, errors.New("refresh returned no access token")
	}

	log := zerolog.Ctx(r.Context())
	log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Bool("token_refreshed", true)
	})

	refreshed := Session{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, Expiry: token.Expiry}
	if err := cookies.Set(w, refreshed); err != nil {
		log.Error().Err(err).Msg("failed to write refreshed session cookies")
	}
	return refreshed, nil
}

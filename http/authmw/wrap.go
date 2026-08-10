// Package authmw provides a shared HTTP middleware-wrapping helper for
// request-based authenticators (basic, github, hmac).
//
// It is a dependency-free leaf package: the root http package imports
// basic/github/hmac to build handlers from config, so those adapter packages
// cannot import the root http package (or anything that does) without an
// import cycle. authmw has no such dependency, so any of them can import it.
package authmw

import (
	"context"
	"net/http"
)

// AuthRequestFunc authenticates an HTTP request, returning an enriched
// context on success. A Handler's AuthRequest method satisfies this type.
type AuthRequestFunc func(r *http.Request) (context.Context, error)

// Wrap adapts authenticate into an http.Handler wrapping next: on each
// request it calls authenticate; on error, onError writes the response and
// the chain stops there; on success, next runs with the authenticated
// context.
func Wrap(authenticate AuthRequestFunc, next http.Handler, onError func(w http.ResponseWriter, r *http.Request, err error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := authenticate(r)
		if err != nil {
			onError(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

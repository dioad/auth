package browsersession

import (
	"io/fs"
	"net/http"
	"strings"
)

// SPAHandler serves a single-page app from staticFS. A path that names a file
// is served as that file. Any other path is served index.html, so the app's
// client-side routes survive a page reload.
func SPAHandler(staticFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(staticFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(staticFS, path); err != nil {
			// Rewrite to "/", not "/index.html": FileServer answers a request
			// for "/index.html" with a redirect to "./", which the browser
			// resolves against the deep path it asked for.
			r = r.Clone(r.Context())
			r.URL.Path = "/"
			r.URL.RawPath = ""
		}
		fileServer.ServeHTTP(w, r)
	})
}

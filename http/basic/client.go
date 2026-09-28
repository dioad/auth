package basic

import "net/http"

// RoundTripper adds HTTP Basic credentials to every request before
// delegating to Base (or http.DefaultTransport if Base is nil).
type RoundTripper struct {
	Username string
	Password string
	Base     http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Username != "" && t.Password != "" {
		req.SetBasicAuth(t.Username, t.Password)
	}

	if t.Base == nil {
		return http.DefaultTransport.RoundTrip(req)
	}

	return t.Base.RoundTrip(req)
}

package hmac

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ClientAuth implements authentication for an HMAC client.
type ClientAuth struct {
	Config ClientConfig
}

// AddAuth adds the HMAC token to the request's Authorization header.
// The token is generated using the SharedKey, Method, Path, Timestamp, Principal,
// and specified headers, which allows servers to detect tampering and replay attacks.
func (a ClientAuth) AddAuth(req *http.Request) error {
	// Read the request body
	bodyBytes := []byte{}
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		// Restore the request body for subsequent use
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		// If GetBody is not set, configure it so that the request can be retried.
		if req.GetBody == nil {
			bodyCopy := append([]byte(nil), bodyBytes...)
			req.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bodyCopy)), nil
			}
		}
	}

	timestampHeader := a.Config.TimestampHeader
	if timestampHeader == "" {
		timestampHeader = DefaultTimestampHeader
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set(timestampHeader, timestamp)

	if len(a.Config.SignedHeaders) > 0 {
		req.Header.Set(DefaultSignedHeadersHeader, strings.Join(a.Config.SignedHeaders, ","))
	}

	principal := a.Config.Principal

	// Generate canonical data and token
	data := CanonicalData(req, principal, timestamp, a.Config.SignedHeaders, bodyBytes)
	token, err := HMACKey([]byte(a.Config.SharedKey), []byte(data))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("%s %s:%s", AuthScheme, principal, token))

	return nil
}

// HTTPClient returns an http.Client that automatically adds the HMAC token to requests.
func (a ClientAuth) HTTPClient() *http.Client {
	return &http.Client{
		Transport: &HMACRoundTripper{
			Config: a.Config,
		},
	}
}

// HMACRoundTripper is an http.RoundTripper that adds HMAC authentication.
type HMACRoundTripper struct {
	Config ClientConfig
	Base   http.RoundTripper
}

// RoundTrip executes a single HTTP transaction, adding HMAC authentication.
func (t *HMACRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	req = req.Clone(req.Context())

	clientAuth := ClientAuth{Config: t.Config}
	if err := clientAuth.AddAuth(req); err != nil {
		return nil, err
	}

	if t.Base == nil {
		return http.DefaultTransport.RoundTrip(req)
	}

	return t.Base.RoundTrip(req)
}

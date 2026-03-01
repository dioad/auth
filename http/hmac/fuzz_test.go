package hmac

import (
	"bytes"
	"net/http"
	"testing"
)

func FuzzCanonicalData(f *testing.F) {
	f.Add("POST", "/api/data", "id=123", "user123", "1234567890", "Content-Type", []byte(`{"data": true}`))
	f.Fuzz(func(t *testing.T, method, path, query, principal, timestamp, headerName string, body []byte) {
		req, err := http.NewRequest(method, "http://example.com"+path, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.URL.RawQuery = query
		req.Header.Set(headerName, "some-value")

		got := CanonicalData(req, principal, timestamp, []string{headerName}, body)
		if got == "" {
			t.Errorf("CanonicalData returned empty string")
		}
	})
}

func FuzzAuthRequest(f *testing.F) {
	cfg := ServerConfig{
		CommonConfig: CommonConfig{
			SharedKey: "test-secret",
		},
	}
	handler := NewHandler(cfg)

	f.Add("HMAC user123:signature", "1234567890", "Content-Type", []byte("body"))
	f.Fuzz(func(t *testing.T, authHeader, timestamp, signedHeaders string, body []byte) {
		req, err := http.NewRequest("POST", "http://example.com/api", bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Authorization", authHeader)
		req.Header.Set(DefaultTimestampHeader, timestamp)
		req.Header.Set(DefaultSignedHeadersHeader, signedHeaders)

		_, _ = handler.AuthRequest(req)
	})
}

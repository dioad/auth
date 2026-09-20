package hmac

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHeaderCaseNormalization verifies that header names are normalized to lowercase
// in the canonical data, preventing signature mismatches when client and server use
// different casing conventions (e.g., "Content-Type" vs "content-type").
func TestHeaderCaseNormalization(t *testing.T) {
	const sharedKey = "test-secret"
	const principalID = "user123"

	// Test with various case combinations
	testCases := []struct {
		name               string
		clientHeaders      []string
		serverHeaders      []string
		headerValues       map[string]string
		shouldAuthenticate bool
	}{
		{
			name:          "Same case - uppercase",
			clientHeaders: []string{"Content-Type", "X-Api-Key"},
			serverHeaders: []string{"Content-Type", "X-Api-Key"},
			headerValues: map[string]string{
				"Content-Type": "application/json",
				"X-Api-Key":    "secret123",
			},
			shouldAuthenticate: true,
		},
		{
			name:          "Same case - lowercase",
			clientHeaders: []string{"content-type", "x-api-key"},
			serverHeaders: []string{"content-type", "x-api-key"},
			headerValues: map[string]string{
				"content-type": "application/json",
				"x-api-key":    "secret123",
			},
			shouldAuthenticate: true,
		},
		{
			name:          "Different case - client uppercase, server lowercase",
			clientHeaders: []string{"Content-Type", "X-Api-Key"},
			serverHeaders: []string{"content-type", "x-api-key"},
			headerValues: map[string]string{
				"Content-Type": "application/json",
				"X-Api-Key":    "secret123",
			},
			shouldAuthenticate: true,
		},
		{
			name:          "Different case - client lowercase, server uppercase",
			clientHeaders: []string{"content-type", "x-api-key"},
			serverHeaders: []string{"Content-Type", "X-Api-Key"},
			headerValues: map[string]string{
				"content-type": "application/json",
				"x-api-key":    "secret123",
			},
			shouldAuthenticate: true,
		},
		{
			name:          "Mixed case combinations",
			clientHeaders: []string{"CONTENT-TYPE", "x-API-key"},
			serverHeaders: []string{"content-type", "X-Api-Key"},
			headerValues: map[string]string{
				"CONTENT-TYPE": "application/json",
				"x-API-key":    "secret123",
			},
			shouldAuthenticate: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create server with specified header names
			serverHandler := NewHandler(ServerConfig{
				CommonConfig: CommonConfig{
					SharedKey:     sharedKey,
					SignedHeaders: tc.serverHeaders,
				},
			})

			testServer := httptest.NewServer(
				serverHandler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				})),
			)
			defer testServer.Close()

			// Create client with specified header names
			clientAuth := ClientAuth{
				Config: ClientConfig{
					CommonConfig: CommonConfig{
						SharedKey:     sharedKey,
						SignedHeaders: tc.clientHeaders,
					},
					Principal: principalID,
				},
			}

			// Create request and set headers
			req, err := http.NewRequest("POST", testServer.URL+"/api", bytes.NewBufferString(`{"test": true}`))
			require.NoError(t, err, "failed to create request")

			// Set header values using client's header names and distinct values
			for _, headerName := range tc.clientHeaders {
				if val, ok := tc.headerValues[headerName]; ok {
					req.Header.Set(headerName, val)
				}
			}

			// Add authentication
			require.NoError(t, clientAuth.AddAuth(req), "failed to add auth")

			// Make request
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err, "request failed")
			defer func() { _ = resp.Body.Close() }()

			// Verify authentication result
			if tc.shouldAuthenticate {
				assert.Equal(t, http.StatusOK, resp.StatusCode, "expected authentication to succeed")
			} else {
				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "expected authentication to fail")
			}
		})
	}
}

// TestCanonicalDataCaseNormalization directly tests that the CanonicalData function
// produces the same output regardless of header name casing.
func TestCanonicalDataCaseNormalization(t *testing.T) {
	// Create two requests with identical data but different header casing
	req1, err := http.NewRequest("POST", "http://example.com/api?id=123", bytes.NewBufferString(`{"data": true}`))
	require.NoError(t, err, "failed to create request req1")
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-Api-Key", "secret123")

	req2, err := http.NewRequest("POST", "http://example.com/api?id=123", bytes.NewBufferString(`{"data": true}`))
	require.NoError(t, err, "failed to create request req2")
	req2.Header.Set("content-type", "application/json")
	req2.Header.Set("x-api-key", "secret123")

	const principal = "user123"
	const timestamp = "1234567890"

	// Generate canonical data with uppercase header names
	canonical1 := CanonicalData(req1, principal, timestamp, []string{"Content-Type", "X-Api-Key"}, []byte(`{"data": true}`))

	// Generate canonical data with lowercase header names
	canonical2 := CanonicalData(req2, principal, timestamp, []string{"content-type", "x-api-key"}, []byte(`{"data": true}`))

	// The canonical data should be identical
	assert.Equal(t, canonical1, canonical2, "canonical data mismatch")
}

// TestCanonicalData_ProducesExpectedFormat pins the exact byte layout of the
// canonical string. Equality-between-two-calls tests (as above) cannot catch
// a component silently dropped from the signed data, since both sides of the
// comparison drop it identically; this test asserts on the literal signed
// string so a dropped method, path, timestamp, principal, header, or body
// segment is detected directly.
func TestCanonicalData_ProducesExpectedFormat(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/api/data?id=123", bytes.NewBufferString("body-content"))
	require.NoError(t, err)
	req.Header.Set("X-Api-Key", "  secret123  ")
	req.Header.Set("Content-Type", "application/json")

	canonical := CanonicalData(req, "user123", "1700000000", []string{"X-Api-Key", "Content-Type"}, []byte("body-content"))

	expected := "POST\n" +
		"/api/data?id=123\n" +
		"1700000000\n" +
		"user123\n" +
		"x-api-key,content-type\n" +
		"x-api-key:secret123\n" +
		"content-type:application/json\n" +
		"body-content"
	assert.Equal(t, expected, canonical)
}

// TestCanonicalData_DefaultsEmptyPathToSlash verifies the empty-path fallback
// and the omission of the "?" segment when there are no query parameters.
func TestCanonicalData_DefaultsEmptyPathToSlash(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	require.NoError(t, err)

	canonical := CanonicalData(req, "user123", "1700000000", nil, nil)

	expected := "GET\n" +
		"/\n" +
		"1700000000\n" +
		"user123\n" +
		"\n"
	assert.Equal(t, expected, canonical)
}

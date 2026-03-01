package hmac

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
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
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			// Set header values using client's header names and distinct values
			for _, headerName := range tc.clientHeaders {
				if val, ok := tc.headerValues[headerName]; ok {
					req.Header.Set(headerName, val)
				}
			}

			// Add authentication
			if err := clientAuth.AddAuth(req); err != nil {
				t.Fatalf("failed to add auth: %v", err)
			}

			// Make request
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			// Verify authentication result
			if tc.shouldAuthenticate {
				if resp.StatusCode != http.StatusOK {
					t.Errorf("expected authentication to succeed (200), got %d", resp.StatusCode)
				}
			} else {
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("expected authentication to fail (401), got %d", resp.StatusCode)
				}
			}
		})
	}
}

// TestCanonicalDataCaseNormalization directly tests that the CanonicalData function
// produces the same output regardless of header name casing.
func TestCanonicalDataCaseNormalization(t *testing.T) {
	// Create two requests with identical data but different header casing
	req1, err := http.NewRequest("POST", "http://example.com/api?id=123", bytes.NewBufferString(`{"data": true}`))
	if err != nil {
		t.Fatalf("failed to create request req1: %v", err)
	}
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-Api-Key", "secret123")

	req2, err := http.NewRequest("POST", "http://example.com/api?id=123", bytes.NewBufferString(`{"data": true}`))
	if err != nil {
		t.Fatalf("failed to create request req2: %v", err)
	}
	req2.Header.Set("content-type", "application/json")
	req2.Header.Set("x-api-key", "secret123")

	const principal = "user123"
	const timestamp = "1234567890"

	// Generate canonical data with uppercase header names
	canonical1 := CanonicalData(req1, principal, timestamp, []string{"Content-Type", "X-Api-Key"}, []byte(`{"data": true}`))

	// Generate canonical data with lowercase header names
	canonical2 := CanonicalData(req2, principal, timestamp, []string{"content-type", "x-api-key"}, []byte(`{"data": true}`))

	// The canonical data should be identical
	if canonical1 != canonical2 {
		t.Errorf("Canonical data mismatch:\n%q\nvs\n%q", canonical1, canonical2)
	}
}

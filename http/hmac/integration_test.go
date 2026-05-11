package hmac

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authhttp "github.com/dioad/auth/http/context"
)

func TestClientHandlerIntegration(t *testing.T) {
	const sharedKey = "super-secret-key"
	const principalID = "user123"
	const requestBody = `{"action": "create"}`

	serverHandler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{
			SharedKey: sharedKey,
		},
	})

	testServer := httptest.NewServer(
		serverHandler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, _ := authhttp.AuthenticatedPrincipalFromContext(r.Context())
			if principal != principalID {
				t.Errorf("expected principal %q, got %q", principalID, principal)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("authenticated"))
		})),
	)
	defer testServer.Close()

	clientAuth := ClientAuth{
		Config: ClientConfig{
			CommonConfig: CommonConfig{
				SharedKey: sharedKey,
			},
			Principal: principalID,
		},
	}

	req, err := http.NewRequest("POST", testServer.URL+"/action", bytes.NewBufferString(requestBody))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	if err := clientAuth.AddAuth(req); err != nil {
		t.Fatalf("failed to add auth: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestClientHandlerWithSignedHeaders(t *testing.T) {
	const sharedKey = "secret"
	const principalID = "user1"
	const customHeader = "X-Custom-Value"
	const customValue = "foobar"

	serverHandler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{
			SharedKey:     sharedKey,
			SignedHeaders: []string{customHeader},
		},
	})

	testServer := httptest.NewServer(
		serverHandler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})),
	)
	defer testServer.Close()

	clientAuth := ClientAuth{
		Config: ClientConfig{
			CommonConfig: CommonConfig{
				SharedKey:     sharedKey,
				SignedHeaders: []string{customHeader},
			},
			Principal: principalID,
		},
	}

	req, err := http.NewRequest("GET", testServer.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set(customHeader, customValue)

	if err := clientAuth.AddAuth(req); err != nil {
		t.Fatalf("AddAuth failed: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Now try with modified header value
	req2, err := http.NewRequest("GET", testServer.URL, nil)
	if err != nil {
		t.Fatalf("failed to create tampered request: %v", err)
	}
	req2.Header.Set(customHeader, "WRONG")
	// Manually copy the auth headers from previous request to simulate tampering
	req2.Header.Set("Authorization", req.Header.Get("Authorization"))
	req2.Header.Set(DefaultTimestampHeader, req.Header.Get(DefaultTimestampHeader))
	req2.Header.Set(DefaultSignedHeadersHeader, req.Header.Get(DefaultSignedHeadersHeader))

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("failed to make tampered request: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for tampered header, got %d", resp2.StatusCode)
	}
}

func TestTimestampExpiry(t *testing.T) {
	const sharedKey = "secret"
	serverHandler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{
			SharedKey: sharedKey,
		},
		MaxTimestampDiff: 1 * time.Second,
	})

	testServer := httptest.NewServer(serverHandler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	defer testServer.Close()

	clientAuth := ClientAuth{
		Config: ClientConfig{
			CommonConfig: CommonConfig{SharedKey: sharedKey},
			Principal:    "user",
		},
	}

	req, err := http.NewRequest("GET", testServer.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	if err := clientAuth.AddAuth(req); err != nil {
		t.Fatalf("failed to add auth: %v", err)
	}

	// Wait for expiry
	time.Sleep(2 * time.Second)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired timestamp, got %d", resp.StatusCode)
	}
}

func TestWrongPathOrMethod(t *testing.T) {
	const sharedKey = "secret"
	serverHandler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{SharedKey: sharedKey},
	})

	testServer := httptest.NewServer(serverHandler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	defer testServer.Close()

	clientAuth := ClientAuth{
		Config: ClientConfig{
			CommonConfig: CommonConfig{SharedKey: sharedKey},
			Principal:    "user",
		},
	}

	req, err := http.NewRequest("GET", testServer.URL+"/valid", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	if err := clientAuth.AddAuth(req); err != nil {
		t.Fatalf("failed to add auth: %v", err)
	}

	// Change path manually
	req.URL.Path = "/invalid"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong path, got %d", resp.StatusCode)
	}
}

func TestPrincipalSpoofing(t *testing.T) {
	const sharedKey = "super-secret-key"
	const userPrincipal = "user123"
	const adminPrincipal = "admin"

	serverHandler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{SharedKey: sharedKey},
	})

	testServer := httptest.NewServer(serverHandler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	defer testServer.Close()

	clientAuth := ClientAuth{Config: ClientConfig{
		CommonConfig: CommonConfig{SharedKey: sharedKey},
		Principal:    userPrincipal,
	}}

	req1, err := http.NewRequest("POST", testServer.URL, bytes.NewBufferString("body"))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	if err := clientAuth.AddAuth(req1); err != nil {
		t.Fatalf("failed to add auth: %v", err)
	}

	// Capture the valid token for userPrincipal
	authHeader := req1.Header.Get("Authorization")

	// Attacker reuses the signature but changes the principal in the Authorization header
	// Authorization: HMAC user123:signature -> Authorization: HMAC admin:signature
	parts := strings.Split(authHeader, " ")
	creds := parts[1]
	signature := strings.Split(creds, ":")[1]
	spoofedAuthHeader := fmt.Sprintf("HMAC %s:%s", adminPrincipal, signature)

	req2, err := http.NewRequest("POST", testServer.URL, bytes.NewBufferString("body"))
	if err != nil {
		t.Fatalf("failed to create spoofed request: %v", err)
	}
	req2.Header.Set("Authorization", spoofedAuthHeader)
	req2.Header.Set(DefaultTimestampHeader, req1.Header.Get(DefaultTimestampHeader))

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for spoofed principal, got %d", resp2.StatusCode)
	}
}

func TestHMACRoundTripper(t *testing.T) {
	const sharedKey = "secret"
	const principalID = "round-tripper-user"

	serverHandler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{SharedKey: sharedKey},
	})

	testServer := httptest.NewServer(serverHandler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer testServer.Close()

	client := &http.Client{
		Transport: &HMACRoundTripper{
			Config: ClientConfig{
				CommonConfig: CommonConfig{SharedKey: sharedKey},
				Principal:    principalID,
			},
		},
	}

	resp, err := client.Get(testServer.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHeaderWhitespaceHandling(t *testing.T) {
	const sharedKey = "secret"
	const principalID = "user"
	const customHeader = "X-Custom-Value"
	const customValue = "test-value"

	serverHandler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{
			SharedKey:     sharedKey,
			SignedHeaders: []string{customHeader},
		},
	})

	testServer := httptest.NewServer(
		serverHandler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})),
	)

	defer testServer.Close()

	clientAuth := ClientAuth{
		Config: ClientConfig{
			CommonConfig: CommonConfig{
				SharedKey:     sharedKey,
				SignedHeaders: []string{customHeader},
			},
			Principal: principalID,
		},
	}

	// Test 1: Client sets header with leading/trailing whitespace
	req1, err := http.NewRequest("GET", testServer.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	// Manually set header with whitespace before calling AddAuth
	req1.Header.Set(customHeader, "  "+customValue+"  ")

	if err := clientAuth.AddAuth(req1); err != nil {
		t.Fatalf("AddAuth failed: %v", err)
	}

	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp1.Body.Close() }()
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for header with whitespace, got %d", resp1.StatusCode)
	}

	// Test 2: Verify that server normalizes whitespace for signature verification
	// Create a request with the same header value but different whitespace
	req2, err := http.NewRequest("GET", testServer.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req2.Header.Set(customHeader, customValue) // No whitespace

	if err := clientAuth.AddAuth(req2); err != nil {
		t.Fatalf("AddAuth failed: %v", err)
	}

	// Manually add trailing whitespace to the header after signing
	req2.Header.Set(customHeader, customValue+"   ")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	// This should succeed because the server trims whitespace
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for header with added whitespace, got %d", resp2.StatusCode)
	}
}

func TestQueryParametersInSignature(t *testing.T) {
	const sharedKey = "secret"
	const principalID = "user"

	serverHandler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{SharedKey: sharedKey},
	})

	testServer := httptest.NewServer(serverHandler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	defer testServer.Close()

	clientAuth := ClientAuth{
		Config: ClientConfig{

			CommonConfig: CommonConfig{SharedKey: sharedKey},
			Principal:    principalID,
		},
	}

	// Test 1: Valid request with query parameters
	req1, err := http.NewRequest("GET", testServer.URL+"/api/users?id=123&name=alice", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	if err := clientAuth.AddAuth(req1); err != nil {
		t.Fatalf("failed to add auth: %v", err)

	}

	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp1.Body.Close() }()
	if resp1.StatusCode != http.StatusOK {

		t.Errorf("expected 200 for valid query params, got %d", resp1.StatusCode)
	}

	// Test 2: Different query parameters should produce different signatures
	req2, err := http.NewRequest("GET", testServer.URL+"/api/users?id=456&name=bob", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	if err := clientAuth.AddAuth(req2); err != nil {
		t.Fatalf("failed to add auth: %v", err)
	}

	// Verify signatures are different
	authParts1 := strings.Split(req1.Header.Get("Authorization"), ":")
	authParts2 := strings.Split(req2.Header.Get("Authorization"), ":")
	if len(authParts1) < 2 || len(authParts2) < 2 {
		t.Fatal("invalid Authorization header format")
	}
	sig1 := authParts1[1]
	sig2 := authParts2[1]
	if sig1 == sig2 {
		t.Error("different query parameters should produce different signatures")
	}

	// Test 3: Tampering with query parameters should fail verification
	req3, err := http.NewRequest("GET", testServer.URL+"/api/users?id=123&name=alice", nil)
	if err != nil {
		t.Fatalf("failed to create tampered request: %v", err)
	}
	if err := clientAuth.AddAuth(req3); err != nil {
		t.Fatalf("failed to add auth: %v", err)
	}

	// Change query parameters after signing
	req3.URL.RawQuery = "id=999&name=eve"

	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp3.Body.Close() }()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for tampered query params, got %d", resp3.StatusCode)
	}
}

func TestNoQueryParameters(t *testing.T) {
	const sharedKey = "secret"
	const principalID = "user"

	serverHandler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{SharedKey: sharedKey},
	})

	testServer := httptest.NewServer(serverHandler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer testServer.Close()

	clientAuth := ClientAuth{
		Config: ClientConfig{
			CommonConfig: CommonConfig{SharedKey: sharedKey},
			Principal:    principalID,
		},
	}

	// Test request without query parameters still works
	req, err := http.NewRequest("GET", testServer.URL+"/api/users", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	if err := clientAuth.AddAuth(req); err != nil {
		t.Fatalf("failed to add auth: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for request without query params, got %d", resp.StatusCode)
	}
}

func BenchmarkClientAddAuth(b *testing.B) {
	clientAuth := ClientAuth{
		Config: ClientConfig{
			CommonConfig: CommonConfig{
				SharedKey:     "bench-key",
				SignedHeaders: []string{"Content-Type", "X-Custom"},
			},
			Principal: "bench-user",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		req, _ := http.NewRequest("POST", "http://example.com/api", bytes.NewBufferString(`{"data": true}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Custom", "value")
		b.StartTimer()
		_ = clientAuth.AddAuth(req)
	}
}

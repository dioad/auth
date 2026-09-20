package hmac

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authhttp "github.com/dioad/auth/authctx"
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
			assert.Equal(t, principalID, principal)
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
	require.NoError(t, err, "failed to create request")

	require.NoError(t, clientAuth.AddAuth(req), "failed to add auth")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err, "failed to make request")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
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
	require.NoError(t, err, "failed to create request")
	req.Header.Set(customHeader, customValue)

	require.NoError(t, clientAuth.AddAuth(req), "AddAuth failed")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "failed to make request")
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Now try with modified header value
	req2, err := http.NewRequest("GET", testServer.URL, nil)
	require.NoError(t, err, "failed to create tampered request")
	req2.Header.Set(customHeader, "WRONG")
	// Manually copy the auth headers from previous request to simulate tampering
	req2.Header.Set("Authorization", req.Header.Get("Authorization"))
	req2.Header.Set(DefaultTimestampHeader, req.Header.Get(DefaultTimestampHeader))
	req2.Header.Set(DefaultSignedHeadersHeader, req.Header.Get(DefaultSignedHeadersHeader))

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err, "failed to make tampered request")
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode, "expected 401 for tampered header")
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
	require.NoError(t, err, "failed to create request")
	require.NoError(t, clientAuth.AddAuth(req), "failed to add auth")

	// Wait for expiry
	time.Sleep(2 * time.Second)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "request failed")
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "expected 401 for expired timestamp")
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
	require.NoError(t, err, "failed to create request")
	require.NoError(t, clientAuth.AddAuth(req), "failed to add auth")

	// Change path manually
	req.URL.Path = "/invalid"

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "request failed")
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "expected 401 for wrong path")
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
	require.NoError(t, err, "failed to create request")
	require.NoError(t, clientAuth.AddAuth(req1), "failed to add auth")

	// Capture the valid token for userPrincipal
	authHeader := req1.Header.Get("Authorization")

	// Attacker reuses the signature but changes the principal in the Authorization header
	// Authorization: HMAC user123:signature -> Authorization: HMAC admin:signature
	parts := strings.Split(authHeader, " ")
	creds := parts[1]
	signature := strings.Split(creds, ":")[1]
	spoofedAuthHeader := fmt.Sprintf("HMAC %s:%s", adminPrincipal, signature)

	req2, err := http.NewRequest("POST", testServer.URL, bytes.NewBufferString("body"))
	require.NoError(t, err, "failed to create spoofed request")
	req2.Header.Set("Authorization", spoofedAuthHeader)
	req2.Header.Set(DefaultTimestampHeader, req1.Header.Get(DefaultTimestampHeader))

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err, "request failed")
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode, "expected status 401 for spoofed principal")
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
	require.NoError(t, err, "request failed")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
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
	require.NoError(t, err, "failed to create request")
	// Manually set header with whitespace before calling AddAuth
	req1.Header.Set(customHeader, "  "+customValue+"  ")

	require.NoError(t, clientAuth.AddAuth(req1), "AddAuth failed")

	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err, "request failed")
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp1.StatusCode, "expected 200 for header with whitespace")

	// Test 2: Verify that server normalizes whitespace for signature verification
	// Create a request with the same header value but different whitespace
	req2, err := http.NewRequest("GET", testServer.URL, nil)
	require.NoError(t, err, "failed to create request")
	req2.Header.Set(customHeader, customValue) // No whitespace

	require.NoError(t, clientAuth.AddAuth(req2), "AddAuth failed")

	// Manually add trailing whitespace to the header after signing
	req2.Header.Set(customHeader, customValue+"   ")

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err, "request failed")
	defer func() { _ = resp2.Body.Close() }()
	// This should succeed because the server trims whitespace
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "expected 200 for header with added whitespace")
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
	require.NoError(t, err, "failed to create request")
	require.NoError(t, clientAuth.AddAuth(req1), "failed to add auth")

	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err, "request failed")
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp1.StatusCode, "expected 200 for valid query params")

	// Test 2: Different query parameters should produce different signatures
	req2, err := http.NewRequest("GET", testServer.URL+"/api/users?id=456&name=bob", nil)
	require.NoError(t, err, "failed to create request")
	require.NoError(t, clientAuth.AddAuth(req2), "failed to add auth")

	// Verify signatures are different
	authParts1 := strings.Split(req1.Header.Get("Authorization"), ":")
	authParts2 := strings.Split(req2.Header.Get("Authorization"), ":")
	require.GreaterOrEqual(t, len(authParts1), 2, "invalid Authorization header format")
	require.GreaterOrEqual(t, len(authParts2), 2, "invalid Authorization header format")
	sig1 := authParts1[1]
	sig2 := authParts2[1]
	assert.NotEqual(t, sig2, sig1, "different query parameters should produce different signatures")

	// Test 3: Tampering with query parameters should fail verification
	req3, err := http.NewRequest("GET", testServer.URL+"/api/users?id=123&name=alice", nil)
	require.NoError(t, err, "failed to create tampered request")
	require.NoError(t, clientAuth.AddAuth(req3), "failed to add auth")

	// Change query parameters after signing
	req3.URL.RawQuery = "id=999&name=eve"

	resp3, err := http.DefaultClient.Do(req3)
	require.NoError(t, err, "request failed")
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp3.StatusCode, "expected 401 for tampered query params")
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
	require.NoError(t, err, "failed to create request")
	require.NoError(t, clientAuth.AddAuth(req), "failed to add auth")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "request failed")
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "expected 200 for request without query params")
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

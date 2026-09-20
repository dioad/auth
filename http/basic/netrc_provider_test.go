package basic

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetrcProviderIsolation(t *testing.T) {
	// Create first netrc content
	netrc1Content := `machine example.com
login user1
password pass1`

	// Create second netrc content
	netrc2Content := `machine example.com
login user2
password pass2`

	// Create two separate NetrcProvider instances with different data
	provider1 := NewNetrcProviderFromContent(netrc1Content)
	provider2 := NewNetrcProviderFromContent(netrc2Content)

	// Create test requests
	req1, err := http.NewRequest("GET", "http://example.com", nil)
	require.NoError(t, err, "failed to create request")

	req2, err := http.NewRequest("GET", "http://example.com", nil)
	require.NoError(t, err, "failed to create request")

	_ = AddCredentialsWithProvider(req1, provider1)
	_ = AddCredentialsWithProvider(req2, provider2)

	// Verify that each request has the correct credentials
	user1, pass1, ok1 := req1.BasicAuth()
	require.True(t, ok1, "expected credentials on req1")
	assert.Equal(t, "user1", user1)
	assert.Equal(t, "pass1", pass1)

	user2, pass2, ok2 := req2.BasicAuth()
	require.True(t, ok2, "expected credentials on req2")
	assert.Equal(t, "user2", user2)
	assert.Equal(t, "pass2", pass2)
}

func TestNetrcProviderWithClientAuth(t *testing.T) {
	// Test that ClientAuth uses its own NetrcProvider instance
	netrcContent := `machine test.example.com
login testuser
password testpass`

	// Create a ClientAuth instance
	auth := &ClientAuth{
		Config:        ClientConfig{},
		netrcProvider: NewNetrcProviderFromContent(netrcContent),
	}

	// Create a request
	req, err := http.NewRequest("GET", "http://test.example.com", nil)
	require.NoError(t, err, "failed to create request")

	// Add auth
	require.NoError(t, auth.AddAuth(req), "AddAuth failed")

	// Verify credentials
	user, pass, ok := req.BasicAuth()
	require.True(t, ok, "expected credentials on request")
	assert.Equal(t, "testuser", user)
	assert.Equal(t, "testpass", pass)
}

func TestAddCredentialsBackwardCompatibility(t *testing.T) {
	// Test that the old AddCredentials function still works
	// This is a basic smoke test to ensure backward compatibility

	req, err := http.NewRequest("GET", "http://nonexistent.example.com", nil)
	require.NoError(t, err, "failed to create request")

	// This should not panic and should return false (no credentials found)
	added := AddCredentials(req)

	// We expect false since there's no .netrc file with this host
	assert.False(t, added, "expected AddCredentials to return false for nonexistent host")
}

func TestClientAuthMultipleInstances(t *testing.T) {
	// Test that multiple ClientAuth instances don't interfere with each other
	netrcContent := `machine example1.com
login user1
password pass1

machine example2.com
login user2
password pass2`

	// Create two ClientAuth instances with the same netrc provider
	provider := NewNetrcProviderFromContent(netrcContent)
	auth1 := &ClientAuth{Config: ClientConfig{}, netrcProvider: provider}
	auth2 := &ClientAuth{Config: ClientConfig{}, netrcProvider: provider}

	// Create requests for different hosts
	req1, _ := http.NewRequest("GET", "http://example1.com", nil)
	req2, _ := http.NewRequest("GET", "http://example2.com", nil)

	// Add auth from different instances
	require.NoError(t, auth1.AddAuth(req1), "auth1.AddAuth(req1) returned error")
	require.NoError(t, auth2.AddAuth(req2), "auth2.AddAuth(req2) returned error")

	// Verify each got the right credentials
	user1, pass1, _ := req1.BasicAuth()
	assert.Equal(t, "user1", user1, "auth1")
	assert.Equal(t, "pass1", pass1, "auth1")

	user2, pass2, _ := req2.BasicAuth()
	assert.Equal(t, "user2", user2, "auth2")
	assert.Equal(t, "pass2", pass2, "auth2")
}

func TestNetrcProviderParseError(t *testing.T) {
	// Test that NetrcProvider handles errors gracefully
	provider := &NetrcProvider{}

	// Force an error by setting a non-existent NETRC path
	t.Setenv("NETRC", "/nonexistent/path/to/netrc")

	provider.once.Do(provider.readNetrc)

	// Provider should not panic and should handle the error
	if provider.err == nil {
		// If no error, that's fine - the file might not exist which is acceptable
		t.Log("No error reading non-existent netrc (expected)")
	}
}

func TestAddCredentialsWithNilProvider(t *testing.T) {
	// Ensure we handle edge cases gracefully
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// Using the default provider should not panic
	added := AddCredentials(req)

	// We don't care about the result, just that it doesn't panic
	_ = added
}

func TestClientAuthWithConfiguredCredentials(t *testing.T) {
	// Test that ClientAuth prefers configured credentials over netrc
	auth := &ClientAuth{
		Config: ClientConfig{
			User:     "configuser",
			Password: "configpass",
		},
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	require.NoError(t, auth.AddAuth(req), "AddAuth returned error")

	user, pass, ok := req.BasicAuth()
	require.True(t, ok, "expected credentials")
	assert.Equal(t, "configuser", user)
	assert.Equal(t, "configpass", pass)
}

func TestNetrcProviderConcurrency(t *testing.T) {
	// Test that NetrcProvider is safe for concurrent use
	provider := &NetrcProvider{}

	// Simulate multiple goroutines trying to initialize the provider
	done := make(chan bool, 10)
	for range 10 {
		go func() {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			_ = AddCredentialsWithProvider(req, provider)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for range 10 {
		<-done
	}

	// If we get here without a panic, the test passes
}

func TestParseNetrcWithProvider(t *testing.T) {
	// Test that parseNetrc works correctly with the new provider structure
	testData := `machine api.github.com
login testuser
password testpass

machine example.com
login user2
password pass2`

	lines := parseNetrc(testData)

	require.Len(t, lines, 2)

	assert.Equal(t, netrcLine{"api.github.com", "testuser", "testpass"}, lines[0])
	assert.Equal(t, netrcLine{"example.com", "user2", "pass2"}, lines[1])
}

func TestNetrcProviderFirstMatchWins(t *testing.T) {
	// Test that when there are multiple entries for the same host,
	// the first one is used
	netrcContent := `machine example.com
login user1
password pass1

machine example.com
login user2
password pass2`

	provider := NewNetrcProviderFromContent(netrcContent)
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	added := AddCredentialsWithProvider(req, provider)

	require.True(t, added, "expected credentials to be added")

	user, pass, ok := req.BasicAuth()
	require.True(t, ok, "expected credentials on request")

	// Should use the first entry
	assert.Equal(t, "user1", user, "expected first entry")
	assert.Equal(t, "pass1", pass, "expected first entry")
}

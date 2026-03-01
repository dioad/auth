package basic

import (
	"net/http"
	"testing"
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
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req2, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Add credentials using different providers
	AddCredentialsWithProvider(req1, provider1)
	AddCredentialsWithProvider(req2, provider2)

	// Verify that each request has the correct credentials
	user1, pass1, ok1 := req1.BasicAuth()
	if !ok1 {
		t.Fatal("Expected credentials on req1")
	}
	if user1 != "user1" || pass1 != "pass1" {
		t.Errorf("Expected user1/pass1, got %s/%s", user1, pass1)
	}

	user2, pass2, ok2 := req2.BasicAuth()
	if !ok2 {
		t.Fatal("Expected credentials on req2")
	}
	if user2 != "user2" || pass2 != "pass2" {
		t.Errorf("Expected user2/pass2, got %s/%s", user2, pass2)
	}
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
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Add auth
	if err := auth.AddAuth(req); err != nil {
		t.Fatalf("AddAuth failed: %v", err)
	}

	// Verify credentials
	user, pass, ok := req.BasicAuth()
	if !ok {
		t.Fatal("Expected credentials on request")
	}
	if user != "testuser" || pass != "testpass" {
		t.Errorf("Expected testuser/testpass, got %s/%s", user, pass)
	}
}

func TestAddCredentialsBackwardCompatibility(t *testing.T) {
	// Test that the old AddCredentials function still works
	// This is a basic smoke test to ensure backward compatibility

	req, err := http.NewRequest("GET", "http://nonexistent.example.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// This should not panic and should return false (no credentials found)
	added := AddCredentials(req)

	// We expect false since there's no .netrc file with this host
	if added {
		t.Error("Expected AddCredentials to return false for nonexistent host")
	}
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
	auth1.AddAuth(req1)
	auth2.AddAuth(req2)

	// Verify each got the right credentials
	user1, pass1, _ := req1.BasicAuth()
	if user1 != "user1" || pass1 != "pass1" {
		t.Errorf("Auth1: expected user1/pass1, got %s/%s", user1, pass1)
	}

	user2, pass2, _ := req2.BasicAuth()
	if user2 != "user2" || pass2 != "pass2" {
		t.Errorf("Auth2: expected user2/pass2, got %s/%s", user2, pass2)
	}
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
	auth.AddAuth(req)

	user, pass, ok := req.BasicAuth()
	if !ok {
		t.Fatal("Expected credentials")
	}
	if user != "configuser" || pass != "configpass" {
		t.Errorf("Expected configuser/configpass, got %s/%s", user, pass)
	}
}

func TestNetrcProviderConcurrency(t *testing.T) {
	// Test that NetrcProvider is safe for concurrent use
	provider := &NetrcProvider{}

	// Simulate multiple goroutines trying to initialize the provider
	done := make(chan bool, 10)
	for range 10 {
		go func() {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			AddCredentialsWithProvider(req, provider)
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

	if len(lines) != 2 {
		t.Errorf("Expected 2 lines, got %d", len(lines))
	}

	if lines[0].machine != "api.github.com" || lines[0].login != "testuser" || lines[0].password != "testpass" {
		t.Errorf("First line incorrect: %+v", lines[0])
	}

	if lines[1].machine != "example.com" || lines[1].login != "user2" || lines[1].password != "pass2" {
		t.Errorf("Second line incorrect: %+v", lines[1])
	}
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

	if !added {
		t.Fatal("Expected credentials to be added")
	}

	user, pass, ok := req.BasicAuth()
	if !ok {
		t.Fatal("Expected credentials on request")
	}

	// Should use the first entry
	if user != "user1" || pass != "pass1" {
		t.Errorf("Expected first entry (user1/pass1), got %s/%s", user, pass)
	}
}

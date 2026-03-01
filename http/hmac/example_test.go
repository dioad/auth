package hmac_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	authhttp "github.com/dioad/auth/http/context"
	"github.com/dioad/auth/http/hmac"
)

// Example demonstrates basic HMAC client-server authentication.
func Example() {
	const sharedSecret = "shared-secret-key"
	const userID = "user@example.com"
	const requestBody = `{"action": "update"}`

	// Create a server with HMAC authentication
	handler := hmac.NewHandler(hmac.ServerConfig{
		CommonConfig: hmac.CommonConfig{
			SharedKey: sharedSecret,
		},
	})

	// Wrap the API handler
	api := handler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := authhttp.AuthenticatedPrincipalFromContext(r.Context())
		fmt.Printf("Authenticated user: %s\n", user)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "success")
	}))

	server := httptest.NewServer(api)
	defer server.Close()

	// Create HMAC client
	clientAuth := hmac.ClientAuth{
		Config: hmac.ClientConfig{
			CommonConfig: hmac.CommonConfig{
				SharedKey: sharedSecret,
			},
			Principal: userID,
		},
	}

	req, err := http.NewRequest("POST", server.URL+"/api", bytes.NewBufferString(requestBody))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}
	if err := clientAuth.AddAuth(req); err != nil {
		fmt.Printf("Error adding auth: %v\n", err)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Response: %s\n", string(body))

	// Output:
	// Authenticated user: user@example.com
	// Response: success
}

// ExampleClientAuth_AddAuth demonstrates signing a single request with custom headers.
func ExampleClientAuth_AddAuth() {
	const sharedSecret = "my-secret"
	const userID = "alice"

	handler := hmac.NewHandler(hmac.ServerConfig{
		CommonConfig: hmac.CommonConfig{
			SharedKey:     sharedSecret,
			SignedHeaders: []string{"X-Custom-Header"},
		},
	})

	server := httptest.NewServer(handler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})))
	defer server.Close()

	req, _ := http.NewRequest("POST", server.URL, bytes.NewBufferString("data"))
	req.Header.Set("X-Custom-Header", "important-value")

	clientAuth := hmac.ClientAuth{
		Config: hmac.ClientConfig{
			CommonConfig: hmac.CommonConfig{
				SharedKey:     sharedSecret,
				SignedHeaders: []string{"X-Custom-Header"},
			},
			Principal: userID,
		},
	}
	if err := clientAuth.AddAuth(req); err != nil {
		fmt.Printf("Error adding auth: %v\n", err)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer resp.Body.Close()
	fmt.Println(resp.StatusCode)

	// Output:
	// 200
}

// ExampleClientAuth_AddAuth_requestBinding demonstrates using HMAC to bind to an existing token.
func ExampleClientAuth_AddAuth_requestBinding() {
	const sharedSecret = "secret"
	const jwtToken = "eyXXX.YYY.ZZZ"

	// Server configures HMAC to sign the X-JWT-Token header
	handler := hmac.NewHandler(hmac.ServerConfig{
		CommonConfig: hmac.CommonConfig{
			SharedKey:     sharedSecret,
			SignedHeaders: []string{"X-JWT-Token"},
		},
	})

	server := httptest.NewServer(handler.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "verified binding")
	})))
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	// Add the token we want to bind
	req.Header.Set("X-JWT-Token", jwtToken)

	clientAuth := hmac.ClientAuth{
		Config: hmac.ClientConfig{
			CommonConfig: hmac.CommonConfig{
				SharedKey:     sharedSecret,
				SignedHeaders: []string{"X-JWT-Token"},
			},
			Principal: "client-app",
		},
	}
	if err := clientAuth.AddAuth(req); err != nil {
		fmt.Printf("Error adding auth: %v\n", err)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))

	// Output:
	// verified binding
}

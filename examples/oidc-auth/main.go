package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	authserver "github.com/dioad/auth/http/server"
	"github.com/dioad/auth/oidc"

	diohttp "github.com/dioad/net/http"
)

func main() {
	// Create OIDC validator configuration
	validatorConfig := oidc.ValidatorConfig{
		EndpointConfig: oidc.EndpointConfig{
			Type: "githubactions",
			URL:  "https://token.actions.githubusercontent.com",
		},
		Audiences: []string{"https://github.com/my-org"},
		Issuer:    "https://token.actions.githubusercontent.com",
	}

	// Create a simple handler
	myHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, authenticated user!\n")
	})

	// Create server with OIDC validator as global middleware
	config := diohttp.Config{ListenAddress: ":8080"}
	server := diohttp.NewServer(config, authserver.WithOAuth2Validator([]oidc.ValidatorConfig{validatorConfig}))

	server.AddHandler("/secure", myHandler)

	// Create listener
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Error creating listener: %v\n", err)
	}
	defer ln.Close()

	fmt.Println("Starting HTTP server with OIDC authentication on :8080")
	fmt.Println("Note: This server requires a valid GitHub Actions OIDC token")
	fmt.Println("Try: curl -H 'Authorization: Bearer <token>' http://localhost:8080/secure")

	// Start server in goroutine
	go func() {
		if err := server.Serve(ln); err != nil {
			log.Printf("Server error: %v\n", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down server...")
}

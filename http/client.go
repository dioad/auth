package http

import (
	"net/http"

	"github.com/dioad/generics"

	"github.com/dioad/auth/http/basic"
	"github.com/dioad/auth/http/github"
	"github.com/dioad/auth/http/hmac"
)

// NewRequestModifier returns a request modifier function that applies auth credentials and netrc
// credentials to outgoing requests. It is designed for use with github.com/dioad/net/http.ClientConfig.RequestModifier.
func NewRequestModifier(cfg ClientConfig) func(*http.Request) error {
	return func(req *http.Request) error {
		if !generics.IsZeroValue(cfg) {
			ac := NewClientAuth(cfg)
			if ac != nil {
				if err := ac.AddAuth(req); err != nil {
					return err
				}
			}
		}
		basic.AddCredentials(req)
		return nil
	}
}

// NewClientAuth returns a ClientAuth implementation based on the provided configuration.
func NewClientAuth(authConfig ClientConfig) ClientAuth {
	if !generics.IsZeroValue(authConfig.GitHubAuthConfig) {
		return github.ClientAuth{Config: authConfig.GitHubAuthConfig}
	}
	if !generics.IsZeroValue(authConfig.BasicAuthConfig) {
		return &basic.ClientAuth{Config: authConfig.BasicAuthConfig}
	}
	if !generics.IsZeroValue(authConfig.HMACAuthConfig) {
		return hmac.ClientAuth{Config: authConfig.HMACAuthConfig}
	}
	return nil
}

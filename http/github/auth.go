package github

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/google/go-github/v33/github"
)

// Authenticator handles GitHub token validation using the GitHub API.
type Authenticator struct {
	Config ServerConfig
	Client *github.Client
}

// TokenSource implements the oauth2.TokenSource interface for a static GitHub token.
type TokenSource struct {
	AccessToken string
}

// Token returns the static token.
func (t *TokenSource) Token() (*oauth2.Token, error) {
	token := &oauth2.Token{
		AccessToken: t.AccessToken,
	}
	return token, nil
}

// AuthenticateToken verifies the provided GitHub access token against the GitHub API.
// It also fetches additional user information if the token is valid.
func (a *Authenticator) AuthenticateToken(accessToken string) (*UserInfo, error) {
	_, response, err := a.Client.Authorizations.Check(context.Background(), a.Config.ClientID, accessToken)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to authenticate token: %s", response.Status)
	}

	// get some info
	u, err := FetchUserInfo(accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}

	return u, nil
}

// NewGitHubAuthenticator creates a new GitHub Authenticator with the provided configuration.
func NewGitHubAuthenticator(cfg ServerConfig) *Authenticator {
	basicAuthTransport := github.BasicAuthTransport{
		Username: cfg.ClientID,
		Password: cfg.ClientSecret,
	}

	return &Authenticator{
		Config: cfg,
		Client: github.NewClient(basicAuthTransport.Client()),
	}
}

package github

import (
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

// ClientAuth implements authentication for a GitHub client.
type ClientAuth struct {
	Config      ClientConfig
	accessToken string
}

// AddAuth adds the GitHub access token to the request's Authorization header.
func (a ClientAuth) AddAuth(req *http.Request) error {
	if a.accessToken == "" {
		var err error
		a.accessToken, err = ResolveAccessToken(a.Config)
		if err != nil {
			return err
		}
		log.Debug().Str("accessTokenPrefix", a.accessToken[0:8]).Msg("readAccessToken")
	}

	req.Header.Add("Authorization", fmt.Sprintf("bearer %v", a.accessToken))

	return nil
}

// Token implements the oauth2.TokenSource interface.
func (a ClientAuth) Token() (*oauth2.Token, error) {
	if a.accessToken == "" {
		var err error
		a.accessToken, err = ResolveAccessToken(a.Config)
		if err != nil {
			return nil, err
		}
		log.Debug().Str("accessTokenPrefix", a.accessToken[0:8]).Msg("readAccessToken")
	}

	return &oauth2.Token{
		AccessToken: a.accessToken,
	}, nil
}

func (a ClientAuth) HTTPClient() *http.Client {
	return &http.Client{
		Transport: &TokenRoundTripper{
			Source: &a,
		},
	}
}

// TokenRoundTripper is an http.RoundTripper that adds an OAuth2 token to requests.
type TokenRoundTripper struct {
	Source oauth2.TokenSource
	Base   http.RoundTripper
}

// RoundTrip executes a single HTTP transaction, adding the token to the request.
func (t *TokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Source != nil {

		token, err := t.Source.Token()
		if err != nil {
			return nil, err
		}
		token.SetAuthHeader(req)
	}

	if t.Base == nil {
		return http.DefaultTransport.RoundTrip(req)
	}

	return t.Base.RoundTrip(req)
}

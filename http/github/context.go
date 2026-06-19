package github

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/google/go-github/v33/github"

	"github.com/dioad/auth/authctx"
	"github.com/dioad/generics"
)

// FetchUserInfo retrieves GitHub user information using the provided access token.
// It fetches basic profile info and the primary email address.
func FetchUserInfo(accessToken string) (*authctx.GitHubUserInfo, error) {
	t := &TokenSource{AccessToken: accessToken}
	oauthClient := oauth2.NewClient(context.Background(), t)
	client := github.NewClient(oauthClient)

	u, _, err := client.Users.Get(context.Background(), "")
	if err != nil {
		return nil, err
	}

	emails, _, err := client.Users.ListEmails(context.Background(), &github.ListOptions{PerPage: 10})
	if err != nil {
		return nil, err
	}

	userInfo := &authctx.GitHubUserInfo{
		Login:    u.GetLogin(),
		Name:     u.GetName(),
		WebSite:  u.GetBlog(),
		Company:  u.GetCompany(),
		Location: u.GetLocation(),
		PlanName: u.GetPlan().GetName(),
	}

	primaryEmail, err := generics.SelectOne(emails, func(e *github.UserEmail) bool {
		return e.GetPrimary()
	})
	if err != nil {
		return nil, err
	}

	userInfo.PrimaryEmail = primaryEmail.GetEmail()
	userInfo.PrimaryEmailVerified = primaryEmail.GetVerified()

	return userInfo, nil
}

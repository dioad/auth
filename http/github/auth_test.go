package github

import (
	"testing"
)

func TestGitHubAuthenticator_AuthenticateToken(t *testing.T) {
	t.Skip("Skipping test that requires network access or complex mocking of github.Client")
	tests := map[string]struct {
		token   string
		userNil bool
		login   string
	}{
		// /		"valid token":   {token: "64b9d04d389defed0c7d80abcc164a6f3c8912cd4", userNil: false, login: "patdowney"},
		"invalid token": {token: "somethinegelse", userNil: true},
	}

	authenticator := NewGitHubAuthenticator(ServerConfig{
		CommonConfig: CommonConfig{
			ClientID:     "bbf369ec17928529a7e8",
			ClientSecret: "491c7ea4efeff78bb7944fb70381cb9c33aca7a3",
		},
	})

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			user, _ := authenticator.AuthenticateToken(tc.token)
			if tc.userNil && user != nil {
				t.Fatalf("expected nil user, got %v", user.Login)
			}

			if !tc.userNil {
				if user == nil {
					t.Fatalf("did not expect nil user")
				}
				if user.Login != tc.login {
					t.Fatalf("expected %v, got %v", tc.login, user.Login)
				}
			}
		})
	}
}

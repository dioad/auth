package github

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authhttp "github.com/dioad/auth/authctx"
)

type mockAuthenticator struct {
	user *authhttp.GitHubUserInfo
	err  error
}

func (m *mockAuthenticator) AuthenticateToken(accessToken string) (*authhttp.GitHubUserInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

func TestHandler_AuthRequest(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		mockUser      *authhttp.GitHubUserInfo
		mockErr       error
		wantPrincipal string
		wantError     bool
	}{
		{
			name:          "valid bearer token",
			authHeader:    "Bearer valid-token",
			mockUser:      &authhttp.GitHubUserInfo{Login: "test-user"},
			wantPrincipal: "test-user",
			wantError:     false,
		},
		{
			name:          "valid token scheme",
			authHeader:    "Token valid-token",
			mockUser:      &authhttp.GitHubUserInfo{Login: "test-user"},
			wantPrincipal: "test-user",
			wantError:     false,
		},
		{
			name:       "invalid auth header format",
			authHeader: "Bearer",
			wantError:  true,
		},
		{
			name:       "invalid auth type",
			authHeader: "Basic user:pass",
			wantError:  true,
		},
		{
			name:       "authenticator error",
			authHeader: "Bearer invalid-token",
			mockErr:    fmt.Errorf("auth failed"),
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authenticator := &mockAuthenticator{user: tt.mockUser, err: tt.mockErr}
			handler := NewHandlerWithAuthenticator(authenticator)

			req := httptest.NewRequest("GET", "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			ctx, err := handler.AuthRequest(req)

			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			principal, _ := authhttp.AuthenticatedPrincipalFromContext(ctx)
			assert.Equal(t, tt.wantPrincipal, principal)

			user := authhttp.GitHubUserInfoFromContext(ctx)
			if assert.NotNil(t, user, "expected user info in context") {
				assert.Equal(t, tt.wantPrincipal, user.Login)
			}
		})
	}
}

func TestHandler_Wrap(t *testing.T) {
	authenticator := &mockAuthenticator{user: &authhttp.GitHubUserInfo{Login: "test-user"}}
	handler := NewHandlerWithAuthenticator(authenticator)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := authhttp.AuthenticatedPrincipalFromContext(r.Context())
		assert.Equal(t, "test-user", principal)
		w.WriteHeader(http.StatusOK)
	})

	wrapped := handler.Wrap(testHandler)

	// Valid request
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Invalid request
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	authenticator.err = fmt.Errorf("auth failed")
	rr = httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

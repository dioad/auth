package github

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	authhttp "github.com/dioad/auth/http/context"
)

type mockAuthenticator struct {
	user *UserInfo
	err  error
}

func (m *mockAuthenticator) AuthenticateToken(accessToken string) (*UserInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

func TestHandler_AuthRequest(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		mockUser      *UserInfo
		mockErr       error
		wantPrincipal string
		wantError     bool
	}{
		{
			name:          "valid bearer token",
			authHeader:    "Bearer valid-token",
			mockUser:      &UserInfo{Login: "test-user"},
			wantPrincipal: "test-user",
			wantError:     false,
		},
		{
			name:          "valid token scheme",
			authHeader:    "Token valid-token",
			mockUser:      &UserInfo{Login: "test-user"},
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

			if (err != nil) != tt.wantError {
				t.Errorf("AuthRequest() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				principal, _ := authhttp.AuthenticatedPrincipalFromContext(ctx)
				if principal != tt.wantPrincipal {
					t.Errorf("expected principal %s, got %s", tt.wantPrincipal, principal)
				}

				user := GitHubUserInfoFromContext(ctx)
				if user == nil || user.Login != tt.wantPrincipal {
					t.Errorf("expected user info in context, got %v", user)
				}
			}
		})
	}
}

func TestHandler_Wrap(t *testing.T) {
	authenticator := &mockAuthenticator{user: &UserInfo{Login: "test-user"}}
	handler := NewHandlerWithAuthenticator(authenticator)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := authhttp.AuthenticatedPrincipalFromContext(r.Context())
		if principal != "test-user" {
			t.Errorf("expected principal test-user, got %s", principal)
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := handler.Wrap(testHandler)

	// Valid request
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Invalid request
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	authenticator.err = fmt.Errorf("auth failed")
	rr = httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rr.Code)
	}
}

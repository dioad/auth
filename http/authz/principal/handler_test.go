package principal

import (
	"net/http"
	"net/http/httptest"
	"testing"

	authhttp "github.com/dioad/auth/http/context"

	"github.com/dioad/net/authz"
)

func TestHandlerFunc(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"user@example.com"},
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	handlerFunc := HandlerFunc(cfg, nextHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := authhttp.ContextWithAuthenticatedPrincipal(req.Context(), "user@example.com")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handlerFunc(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}
	if w.Body.String() != "success" {
		t.Errorf("Expected body %q, got %q", "success", w.Body.String())
	}
}

func TestNewHandler(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"admin@example.com"},
		DenyList:  []string{"banned@example.com"},
	}

	handler := NewHandler(cfg)

	if handler == nil {
		t.Fatal("Expected handler to be created, got nil")
	}
	if len(handler.Config.AllowList) != 1 {
		t.Errorf("Expected 1 item in AllowList, got %d", len(handler.Config.AllowList))
	}
	if len(handler.Config.DenyList) != 1 {
		t.Errorf("Expected 1 item in DenyList, got %d", len(handler.Config.DenyList))
	}
}

func TestAuthRequest_Authorized(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"alice@example.com", "bob@example.com"},
	}

	handler := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := authhttp.ContextWithAuthenticatedPrincipal(req.Context(), "alice@example.com")
	req = req.WithContext(ctx)

	resultCtx, err := handler.AuthRequest(req)

	if err != nil {
		t.Errorf("Expected no error for authorised principal, got: %v", err)
	}
	if resultCtx == nil {
		t.Error("Expected context to be returned")
	}
}

func TestAuthRequest_Unauthorised(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"alice@example.com"},
	}

	handler := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := authhttp.ContextWithAuthenticatedPrincipal(req.Context(), "eve@example.com")
	req = req.WithContext(ctx)

	_, err := handler.AuthRequest(req)

	if err == nil {
		t.Error("Expected error for unauthorised principal, got nil")
	}
}

func TestAuthRequest_NoPrincipal(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"alice@example.com"},
	}

	handler := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/test", nil)

	_, err := handler.AuthRequest(req)

	if err == nil {
		t.Error("Expected error for missing principal, got nil")
	}
}

func TestAuthRequest_DenyList(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"*"},
		DenyList:  []string{"banned@example.com"},
	}

	handler := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := authhttp.ContextWithAuthenticatedPrincipal(req.Context(), "banned@example.com")
	req = req.WithContext(ctx)

	_, err := handler.AuthRequest(req)

	if err == nil {
		t.Error("Expected error for denied principal, got nil")
	}
}

func TestWrap_Authorised(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"admin@example.com"},
	}

	handler := NewHandler(cfg)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authorized"))
	})

	wrappedHandler := handler.Wrap(nextHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := authhttp.ContextWithAuthenticatedPrincipal(req.Context(), "admin@example.com")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}
	if w.Body.String() != "authorized" {
		t.Errorf("Expected body %q, got %q", "authorized", w.Body.String())
	}
}

func TestWrap_Forbidden(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"admin@example.com"},
	}

	handler := NewHandler(cfg)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called for forbidden request")
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := handler.Wrap(nextHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := authhttp.ContextWithAuthenticatedPrincipal(req.Context(), "user@example.com")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestWrap_NoPrincipal(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"admin@example.com"},
	}

	handler := NewHandler(cfg)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called when no principal is present")
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := handler.Wrap(nextHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	// No principal in context → 401 Unauthorized (not 403 Forbidden)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

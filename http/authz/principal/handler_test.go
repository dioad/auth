package principal

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authhttp "github.com/dioad/auth/authctx"

	"github.com/dioad/net/authz"
)

func TestHandlerFunc(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"user@example.com"},
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	handlerFunc := HandlerFunc(cfg, nextHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := authhttp.ContextWithAuthenticatedPrincipal(req.Context(), "user@example.com")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handlerFunc(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "success", w.Body.String())
}

func TestNewHandler(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"admin@example.com"},
		DenyList:  []string{"banned@example.com"},
	}

	handler := NewHandler(cfg)

	require.NotNil(t, handler)
	assert.Len(t, handler.Config.AllowList, 1)
	assert.Len(t, handler.Config.DenyList, 1)
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

	assert.NoError(t, err, "expected no error for authorised principal")
	assert.NotNil(t, resultCtx, "expected context to be returned")
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

	assert.Error(t, err, "expected error for unauthorised principal")
}

func TestAuthRequest_NoPrincipal(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"alice@example.com"},
	}

	handler := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/test", nil)

	_, err := handler.AuthRequest(req)

	assert.Error(t, err, "expected error for missing principal")
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

	assert.Error(t, err, "expected error for denied principal")
}

func TestWrap_Authorised(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"admin@example.com"},
	}

	handler := NewHandler(cfg)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("authorized"))
	})

	wrappedHandler := handler.Wrap(nextHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := authhttp.ContextWithAuthenticatedPrincipal(req.Context(), "admin@example.com")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "authorized", w.Body.String())
}

func TestWrap_Forbidden(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"admin@example.com"},
	}

	handler := NewHandler(cfg)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Fail(t, "next handler should not be called for forbidden request")
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := handler.Wrap(nextHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := authhttp.ContextWithAuthenticatedPrincipal(req.Context(), "user@example.com")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestWrap_NoPrincipal(t *testing.T) {
	cfg := authz.PrincipalACLConfig{
		AllowList: []string{"admin@example.com"},
	}

	handler := NewHandler(cfg)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Fail(t, "next handler should not be called when no principal is present")
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := handler.Wrap(nextHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	// No principal in context → 401 Unauthorized (not 403 Forbidden)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

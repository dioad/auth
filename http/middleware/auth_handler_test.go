package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth"
)

type testPrincipalExtractor struct {
	principal *auth.PrincipalContext
	err       error
}

func (e testPrincipalExtractor) ExtractPrincipal(_ context.Context, _ *http.Request) (*auth.PrincipalContext, error) {
	return e.principal, e.err
}

func TestPrincipalExtractionHandler_NoPrincipalFound_ReturnsUnauthorized(t *testing.T) {
	mw := PrincipalExtractionHandler(testPrincipalExtractor{err: auth.ErrNoPrincipalFound}, zerolog.Nop())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	nextCalled := false
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	})).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.False(t, nextCalled)
}

func TestPrincipalExtractionHandler_NilPrincipal_ReturnsUnauthorized(t *testing.T) {
	mw := PrincipalExtractionHandler(testPrincipalExtractor{}, zerolog.Nop())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	nextCalled := false
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	})).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.False(t, nextCalled)
}

func TestPrincipalExtractionHandler_ExtractorError_ReturnsInternalServerError(t *testing.T) {
	mw := PrincipalExtractionHandler(testPrincipalExtractor{err: errors.New("boom")}, zerolog.Nop())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	nextCalled := false
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	})).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.False(t, nextCalled)
}

func TestPrincipalExtractionHandler_Success_PropagatesPrincipalContext(t *testing.T) {
	expectedPrincipal := &auth.PrincipalContext{ID: "alice", Source: "oidc", Roles: []string{"user-admin"}}
	mw := PrincipalExtractionHandler(testPrincipalExtractor{principal: expectedPrincipal}, zerolog.Nop())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	nextCalled := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		nextCalled = true
		principal := auth.PrincipalContextFromContext(r.Context())
		require.NotNil(t, principal)
		assert.Equal(t, expectedPrincipal, principal)
	})).ServeHTTP(rr, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rr.Code)
}

package oidc

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// HTTPDoer abstracts HTTP calls for testability.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Clock abstracts time for deterministic tests.
type Clock interface {
	Now() time.Time
}

// TokenStore abstracts token persistence.
type TokenStore interface {
	LoadToken(ctx context.Context) (*oauth2.Token, error)
	SaveToken(ctx context.Context, token *oauth2.Token) error
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now()
}

// FileTokenStore persists tokens in a file on disk.
type FileTokenStore struct {
	path string
}

// NewFileTokenStore creates a file-based token store.
func NewFileTokenStore(path string) *FileTokenStore {
	return &FileTokenStore{path: path}
}

// LoadToken reads a token from disk.
func (s *FileTokenStore) LoadToken(_ context.Context) (*oauth2.Token, error) {
	return ResolveTokenFromFile(s.path)
}

// SaveToken writes a token to disk.
func (s *FileTokenStore) SaveToken(_ context.Context, token *oauth2.Token) error {
	return SaveTokenToFile(token, s.path)
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

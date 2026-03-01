package oidc

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestResolveTokenFromFileExpandsHome(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	tokenPath := filepath.Join(tmpHome, ".token.json")
	token := &oauth2.Token{AccessToken: "abc123"}
	require.NoError(t, SaveTokenToFile(token, tokenPath))

	loaded, err := ResolveTokenFromFile("~/.token.json")
	require.NoError(t, err)
	require.Equal(t, "abc123", loaded.AccessToken)
}

func TestResolveTokenFromFileNoExpansion(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "token.json")
	require.NoError(t, SaveTokenToFile(&oauth2.Token{AccessToken: "nohome", Expiry: time.Now().Add(time.Hour)}, path))

	loaded, err := ResolveTokenFromFile(path)
	require.NoError(t, err)
	require.Equal(t, "nohome", loaded.AccessToken)
}

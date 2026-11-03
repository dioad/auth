package oidc

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

// TestResolveTokenFromFileRejectsAFileWithNoToken guards a process polling
// for a token file, which may find it empty: that is no token yet, not an
// empty one to send.
func TestResolveTokenFromFileRejectsAFileWithNoToken(t *testing.T) {
	t.Parallel()

	for name, content := range map[string]string{"token.yaml": "", "token.json": "{}"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), name)
			require.NoError(t, os.WriteFile(path, []byte(content), 0600))

			_, err := ResolveTokenFromFile(path)
			require.ErrorContains(t, err, "holds no token")
		})
	}
}

// TestSaveTokenToFileReplacesTheFileWhole checks that a reader polling the
// file while it is rewritten sees the old token or the new one, never an
// empty or partial file.
func TestSaveTokenToFileReplacesTheFileWhole(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "token.yaml")
	require.NoError(t, SaveTokenToFile(&oauth2.Token{AccessToken: "first"}, path))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			if err := SaveTokenToFile(&oauth2.Token{AccessToken: "second"}, path); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			assert.Len(t, entries, 1, "no temporary files are left behind")
			return
		default:
			token, err := ResolveTokenFromFile(path)
			require.NoError(t, err)
			require.Contains(t, []string{"first", "second"}, token.AccessToken)
		}
	}
}

func TestResolveTokenFromFileNoExpansion(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "token.json")
	require.NoError(t, SaveTokenToFile(&oauth2.Token{AccessToken: "nohome", Expiry: time.Now().Add(time.Hour)}, path))

	loaded, err := ResolveTokenFromFile(path)
	require.NoError(t, err)
	require.Equal(t, "nohome", loaded.AccessToken)
}

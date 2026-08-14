package basic

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAuthMap(t *testing.T, user, password string) AuthMap {
	t.Helper()
	m := AuthMap{}
	m.AddUserWithPlainPassword(user, password)
	return m
}

func TestHandler_SetAuthMap_ReplacesCredentialsLive(t *testing.T) {
	h, err := NewHandlerWithMap(ServerConfig{}, newTestAuthMap(t, "alice", "old-pass"))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("alice", "old-pass")
	_, err = h.AuthRequest(req)
	require.NoError(t, err, "original credentials should authenticate before any swap")

	h.SetAuthMap(newTestAuthMap(t, "alice", "new-pass"))

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("alice", "old-pass")
	_, err = h.AuthRequest(req)
	assert.Error(t, err, "old credentials must stop working once SetAuthMap replaces the map")

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("alice", "new-pass")
	_, err = h.AuthRequest(req)
	assert.NoError(t, err, "new credentials should authenticate immediately after SetAuthMap")
}

func TestHandler_SetAuthMap_ConcurrentWithAuthRequest(t *testing.T) {
	h, err := NewHandlerWithMap(ServerConfig{}, newTestAuthMap(t, "alice", "pass"))
	require.NoError(t, err)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	replacement := newTestAuthMap(t, "alice", "pass") // hash once; the loop only needs to exercise the swap, not rehash every iteration

	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				h.SetAuthMap(replacement)
			}
		}
	})

	// bcrypt comparison is deliberately slow; a handful of concurrent calls is
	// enough for the race detector to catch an unsynchronized read of authMap.
	for range 20 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.SetBasicAuth("alice", "pass")
		_, _ = h.AuthRequest(req) // result not asserted, absence of a data race is the point
	}
	close(stop)
	wg.Wait()
}

func TestHandler_AuthMap_ReflectsLatestSetAuthMap(t *testing.T) {
	h, err := NewHandlerWithMap(ServerConfig{}, AuthMap{})
	require.NoError(t, err)
	assert.Empty(t, h.AuthMap())

	h.SetAuthMap(newTestAuthMap(t, "alice", "pass"))
	assert.True(t, h.AuthMap().UserExists("alice"))
}

func TestHandler_WriteUnauthorized_UsesConfiguredRealm(t *testing.T) {
	h, err := NewHandlerWithMap(ServerConfig{Realm: "Test Realm"}, AuthMap{})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	h.writeUnauthorized(rec, httptest.NewRequest(http.MethodGet, "/", nil), nil)

	assert.Equal(t, `Basic realm="Test Realm"`, rec.Header().Get("WWW-Authenticate"),
		"NewHandlerWithMap must preserve cfg.Realm, matching NewHandler's behavior")
}

func TestLoadBasicAuthFromFileOrEmpty_MissingFileIsEmptyNotError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist")

	authMap, err := LoadBasicAuthFromFileOrEmpty(path)
	require.NoError(t, err)
	assert.Empty(t, authMap)
}

func TestLoadBasicAuthFromFileOrEmpty_OtherErrorsStillPropagate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "htpasswd")
	require.NoError(t, os.WriteFile(path, []byte("alice:hash\n"), 0644)) // wrong permissions on purpose

	_, err := LoadBasicAuthFromFileOrEmpty(path)
	assert.Error(t, err, "a present-but-badly-permissioned file must still error, not be treated as empty")
}

func TestLoadBasicAuthFromFileOrEmpty_ExistingFileLoadsNormally(t *testing.T) {
	path := filepath.Join(t.TempDir(), "htpasswd")
	pair, err := NewBasicAuthPairWithPlainPassword("alice", "secret")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("alice:"+pair.HashedPassword+"\n"), 0600))

	authMap, err := LoadBasicAuthFromFileOrEmpty(path)
	require.NoError(t, err)
	require.True(t, authMap.UserExists("alice"))
}

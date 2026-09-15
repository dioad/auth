package basic

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientAuth_AddAuth_InitializesNetrcProviderWhenNil covers the
// lazy-initialization guard: a zero-value ClientAuth (netrcProvider unset)
// must not panic when netrc-based lookup is needed, and must actually find
// matching credentials -- proving both the provider got created and its
// readNetrc was actually invoked, not silently skipped.
func TestClientAuth_AddAuth_InitializesNetrcProviderWhenNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".netrc")
	require.NoError(t, os.WriteFile(path, []byte("machine example.com\nlogin netrcuser\npassword netrcpass\n"), 0600))
	t.Setenv("NETRC", path)

	a := &ClientAuth{}
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)

	require.NotPanics(t, func() {
		err = a.AddAuth(req)
	})
	require.NoError(t, err)

	user, pass, ok := req.BasicAuth()
	require.True(t, ok)
	assert.Equal(t, "netrcuser", user)
	assert.Equal(t, "netrcpass", pass)
}

// TestClientAuth_AddAuth_UsesFirstMatchingNetrcEntry is the regression test
// for the lookup loop's break: given two netrc entries for the same host,
// only the first must be used. A loop that continues instead of breaking
// would apply the last matching entry rather than the first.
func TestClientAuth_AddAuth_UsesFirstMatchingNetrcEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".netrc")
	content := "machine example.com\nlogin first\npassword firstpass\n\n" +
		"machine example.com\nlogin second\npassword secondpass\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	t.Setenv("NETRC", path)

	a := &ClientAuth{}
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)
	require.NoError(t, a.AddAuth(req))

	user, pass, ok := req.BasicAuth()
	require.True(t, ok)
	assert.Equal(t, "first", user)
	assert.Equal(t, "firstpass", pass)
}

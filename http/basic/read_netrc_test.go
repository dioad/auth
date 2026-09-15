package basic

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadNetrc_PropagatesNetrcPathError(t *testing.T) {
	t.Setenv("NETRC", "")
	t.Setenv("HOME", "")

	p := &NetrcProvider{}
	p.readNetrc()

	require.Error(t, p.err)
	// Skipping this guard falls through to os.ReadFile(filepath.Clean("")),
	// i.e. reading the current directory, which also ends up setting p.err
	// (a non-IsNotExist "is a directory" error) -- so a bare assert.Error
	// can't tell the two failure paths apart.
	assert.ErrorContains(t, p.err, "$HOME is not defined")
}

// TestReadNetrc_MissingFileIsNotAnError covers the os.IsNotExist guard: a
// netrc file that simply doesn't exist must leave p.err nil, not be treated
// like any other read failure.
func TestReadNetrc_MissingFileIsNotAnError(t *testing.T) {
	t.Setenv("NETRC", filepath.Join(t.TempDir(), "does-not-exist"))

	p := &NetrcProvider{}
	p.readNetrc()

	require.NoError(t, p.err)
	assert.Empty(t, p.lines)
}

// TestReadNetrc_NonNotExistReadErrorIsPropagated covers the other side of
// the os.IsNotExist guard: an existing-but-unreadable path (here, a
// directory in place of a file) must set p.err, distinct from the
// missing-file case above.
func TestReadNetrc_NonNotExistReadErrorIsPropagated(t *testing.T) {
	t.Setenv("NETRC", t.TempDir())

	p := &NetrcProvider{}
	p.readNetrc()

	require.Error(t, p.err)
	assert.NotErrorIs(t, p.err, os.ErrNotExist)
}

func TestReadNetrc_ParsesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".netrc")
	require.NoError(t, os.WriteFile(path, []byte("machine example.com\nlogin alice\npassword secret\n"), 0600))
	t.Setenv("NETRC", path)

	p := &NetrcProvider{}
	p.readNetrc()

	require.NoError(t, p.err)
	require.Len(t, p.lines, 1)
	assert.Equal(t, "example.com", p.lines[0].machine)
	assert.Equal(t, "alice", p.lines[0].login)
}

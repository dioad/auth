package basic

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetrcPath_UsesNETRCEnvVarWhenSet(t *testing.T) {
	t.Setenv("NETRC", "/custom/netrc/path")

	path, err := netrcPath()
	require.NoError(t, err)
	assert.Equal(t, "/custom/netrc/path", path)
}

func TestNetrcPath_FallsBackToHomeDirWhenNETRCUnset(t *testing.T) {
	t.Setenv("NETRC", "")
	home, err := os.UserHomeDir()
	require.NoError(t, err, "test environment must have a resolvable home directory")

	path, err := netrcPath()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".netrc"), path)
}

func TestNetrcPath_PropagatesUserHomeDirError(t *testing.T) {
	t.Setenv("NETRC", "")
	t.Setenv("HOME", "")

	_, err := netrcPath()
	require.Error(t, err)
}

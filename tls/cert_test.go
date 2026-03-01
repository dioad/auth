package tls

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadCertPoolFromFile(t *testing.T) {
	certPath, _ := writeTestCert(t)

	pool, err := LoadCertPoolFromFile(certPath)
	require.NoError(t, err)
	require.NotNil(t, pool)
	assert.NotEmpty(t, pool.Subjects())
}

func TestLoadCertPoolFromFS(t *testing.T) {
	certPath, _ := writeTestCert(t)
	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)

	fsys := fstest.MapFS{
		"certs/root.pem": {Data: certPEM, Mode: fs.ModePerm},
	}

	pool, err := LoadCertPoolFromFS(fsys, filepath.ToSlash("certs/root.pem"))
	require.NoError(t, err)
	require.NotNil(t, pool)
	assert.NotEmpty(t, pool.Subjects())
}

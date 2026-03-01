package tls

import (
	"crypto/x509"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

// LoadCertPoolFromFile loads a certificate pool from a PEM file.
func LoadCertPoolFromFile(certPoolPath string) (*x509.CertPool, error) {
	certPoolPathClean := filepath.Clean(certPoolPath)
	fsys := os.DirFS(filepath.Dir(certPoolPathClean))
	return LoadCertPoolFromFS(fsys, filepath.Base(certPoolPathClean))
}

// LoadCertPoolFromFS loads a certificate pool from a PEM file in the provided filesystem.
func LoadCertPoolFromFS(fsys fs.FS, certPoolPath string) (*x509.CertPool, error) {
	if fsys == nil {
		return nil, fmt.Errorf("filesystem is nil")
	}

	certPoolPathClean := path.Clean(certPoolPath)
	certPoolPEM, err := fs.ReadFile(fsys, certPoolPathClean)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(certPoolPEM); !ok {
		return nil, fmt.Errorf("failed to append certificates from PEM file: %s", certPoolPath)
	}

	return certPool, nil
}

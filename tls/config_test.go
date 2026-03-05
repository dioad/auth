package tls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	diotls "github.com/dioad/net/tls"
)

func writeTestCert(t *testing.T) (string, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	return certPath, keyPath
}

func TestNewClientTLSConfigDefaults(t *testing.T) {
	tlsConfig, err := NewClientTLSConfig(ClientConfig{InsecureSkipVerify: true})
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.EqualValues(t, tls.VersionTLS12, tlsConfig.MinVersion)
	assert.True(t, tlsConfig.InsecureSkipVerify)
}

func TestNewClientTLSConfigRequiresCertAndKey(t *testing.T) {
	_, err := NewClientTLSConfig(ClientConfig{Certificate: "cert.pem"})
	assert.Error(t, err)

	_, err = NewClientTLSConfig(ClientConfig{Key: "key.pem"})
	assert.Error(t, err)
}

func TestNewClientTLSConfigLoadsCertificatesAndRootCA(t *testing.T) {
	certPath, keyPath := writeTestCert(t)

	tlsConfig, err := NewClientTLSConfig(ClientConfig{
		Certificate: certPath,
		Key:         keyPath,
		RootCAFile:  certPath,
	})
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Len(t, tlsConfig.Certificates, 1)
	assert.NotNil(t, tlsConfig.RootCAs)
}

func TestNewServerTLSConfigOptional(t *testing.T) {
	ctx := context.Background()
	tlsConfig, err := diotls.NewServerTLSConfig(ctx, diotls.ServerConfig{})
	require.NoError(t, err)
	assert.Nil(t, tlsConfig)
}

func TestNewServerTLSConfigLoadsClientCA(t *testing.T) {
	ctx := context.Background()
	certPath, keyPath := writeTestCert(t)

	tlsConfig, err := diotls.NewServerTLSConfig(ctx, diotls.ServerConfig{
		LocalConfig: diotls.LocalConfig{
			Certificate: certPath,
			Key:         keyPath,
		},
		ClientAuthType: "RequireAndVerifyClientCert",
		ClientCAFile:   certPath,
	})
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Len(t, tlsConfig.Certificates, 1)
	assert.NotNil(t, tlsConfig.ClientCAs)
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
}

func TestLoadCertPoolFromFileErrors(t *testing.T) {
	_, err := LoadCertPoolFromFile(filepath.Join(t.TempDir(), "missing.pem"))
	assert.Error(t, err)

	invalidPath := filepath.Join(t.TempDir(), "invalid.pem")
	require.NoError(t, os.WriteFile(invalidPath, []byte("not-a-pem"), 0600))
	_, err = LoadCertPoolFromFile(invalidPath)
	assert.Error(t, err)
}

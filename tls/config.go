// Package tls provides helper functions for building client and server TLS configurations.
package tls

import (
	"crypto/tls"
	"fmt"
)

// ClientConfig specifies TLS client configuration.
type ClientConfig struct {
	RootCAFile         string `mapstructure:"root-ca-file" json:",omitempty"`
	Certificate        string `mapstructure:"cert" json:",omitempty"`
	Key                string `mapstructure:"key" json:",omitempty"`
	InsecureSkipVerify bool   `mapstructure:"insecure-skip-verify"`
}

// NewClientTLSConfig creates a TLS configuration for a client from the given config.
func NewClientTLSConfig(c ClientConfig) (*tls.Config, error) {
	var tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if (c.Certificate != "" && c.Key == "") || (c.Certificate == "" && c.Key != "") {
		return nil, fmt.Errorf("both certificate and key need to be specified")
	}

	if c.Certificate != "" && c.Key != "" {
		clientCertificate, err := tls.LoadX509KeyPair(c.Certificate, c.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load x509 key pair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCertificate}
	}

	if c.RootCAFile != "" {
		// LoadCertPoolFromFile should be available in this package
		rootCAs, err := LoadCertPoolFromFile(c.RootCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load root CA file: %w", err)
		}
		tlsConfig.RootCAs = rootCAs
	}

	tlsConfig.InsecureSkipVerify = c.InsecureSkipVerify

	return tlsConfig, nil
}

// ServerConfig specifies TLS server configuration.
type ServerConfig struct {
	Certificate string `mapstructure:"cert" json:",omitempty"`
	Key         string `mapstructure:"key" json:",omitempty"`
	ClientCA    string `mapstructure:"client-ca" json:",omitempty"`
}

// NewServerTLSConfig creates a TLS configuration for a server from the given config.
func NewServerTLSConfig(c ServerConfig) (*tls.Config, error) {
	if c.Certificate == "" || c.Key == "" {
		return nil, nil // No TLS
	}

	cert, err := tls.LoadX509KeyPair(c.Certificate, c.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load x509 key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if c.ClientCA != "" {
		clientCAs, err := LoadCertPoolFromFile(c.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("failed to load client CA file: %w", err)
		}
		tlsConfig.ClientCAs = clientCAs
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

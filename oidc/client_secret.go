package oidc

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrClientSecretConflict is returned when both client-secret and
// client-secret-file are set on a ClientConfig.
var ErrClientSecretConflict = errors.New("client-secret and client-secret-file are mutually exclusive")

// Validate reports configuration errors that can be detected without touching
// the filesystem. It deliberately does not read ClientSecretFile, because a
// mounted secret may not exist on the host that validates the config.
func (c *ClientConfig) Validate() error {
	if c.ClientSecret.UnmaskedString() != "" && c.ClientSecretFile != "" {
		return ErrClientSecretConflict
	}
	return nil
}

// ResolveClientSecret returns the client secret, reading ClientSecretFile when
// it is set. Surrounding whitespace in the file is trimmed. It returns an empty
// string and no error when neither client-secret nor client-secret-file is set.
func (c *ClientConfig) ResolveClientSecret() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if c.ClientSecretFile == "" {
		return c.ClientSecret.UnmaskedString(), nil
	}

	data, err := os.ReadFile(c.ClientSecretFile)
	if err != nil {
		return "", fmt.Errorf("reading client-secret-file: %w", err)
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", fmt.Errorf("client-secret-file %q is empty", c.ClientSecretFile)
	}
	return secret, nil
}

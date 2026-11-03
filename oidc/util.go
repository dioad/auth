package oidc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

// SaveTokenToFile saves the provided OAuth2 token to a file.
func SaveTokenToFile(token *oauth2.Token, filePath string) error {
	var data []byte
	var err error

	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".json":
		// #nosec G117
		data, err = json.MarshalIndent(token, "", "  ")
	case ".yaml", ".yml":
		// #nosec G117
		data, err = yaml.Marshal(token)
	default:
		return fmt.Errorf("unsupported file type: %s", filePath)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	expandedPath, err := expandHome(filePath)
	if err != nil {
		return err
	}

	if err := writeFileAtomic(expandedPath, data); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

// writeFileAtomic writes data to a temporary file beside path and renames it
// into place, so a process polling path (an agent waiting for `auth` to sign
// it in) never reads it empty or half-written.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	// CreateTemp creates the file with mode 0600 already.
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ResolveTokenFromFile loads an OAuth2 token from a file. A file that holds
// neither an access token nor a refresh token, such as an empty one, is an
// error rather than an empty token.
func ResolveTokenFromFile(filePath string) (*oauth2.Token, error) {
	expandedPath, err := expandHome(filePath)
	if err != nil {
		return nil, err
	}

	// #nosec G304
	data, err := os.ReadFile(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	var token oauth2.Token
	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".json":
		err = json.Unmarshal(data, &token)
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &token)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", filePath)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}
	if token.AccessToken == "" && token.RefreshToken == "" {
		return nil, fmt.Errorf("token file %s holds no token", filePath)
	}

	return &token, nil
}

func expandHome(path string) (string, error) {
	if path == "" || !strings.HasPrefix(path, "~") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to resolve home directory: %w", err)
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
}

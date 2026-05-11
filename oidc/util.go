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

	err = os.WriteFile(expandedPath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

// ResolveTokenFromFile loads an OAuth2 token from a file.
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

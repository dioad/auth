package github

import (
	"os"

	"github.com/cli/oauth/api"

	"github.com/dioad/util"
)

// LoadAccessTokenFromFile loads a GitHub access token from a file.
func LoadAccessTokenFromFile(filePath string) (*api.AccessToken, error) {
	return util.LoadStructFromFile[api.AccessToken](filePath)
}

// SaveAccessTokenToFile saves a GitHub access token to a file.
func SaveAccessTokenToFile(accessToken *api.AccessToken, authFilePath string) error {
	return util.SaveStructToFile[api.AccessToken](accessToken, authFilePath)
}

// ResolveAccessToken determines the GitHub access token to use based on configuration.
// It checks environment variables if configured, falls back to a file if AccessToken
// is not directly provided in the config.
func ResolveAccessToken(c ClientConfig) (string, error) {

	if c.EnableAccessTokenFromEnvironment {
		if c.EnvironmentVariableName != "" {
			envAccessToken := os.Getenv(c.EnvironmentVariableName)

			if envAccessToken != "" {
				return envAccessToken, nil
			}
		}
	}

	if c.AccessToken == "" {
		// load from c.AccessTokenFile
		token, err := LoadAccessTokenFromFile(c.AccessTokenFile)
		if err != nil {
			return "", err
		}
		return token.Token, nil
	}

	return c.AccessToken, nil
}

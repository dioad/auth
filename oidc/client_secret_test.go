package oidc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/util"
)

func writeSecretFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestClientConfig_ResolveClientSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     func(t *testing.T) ClientConfig
		want    string
		wantErr string
	}{
		{
			name: "neither set",
			cfg:  func(*testing.T) ClientConfig { return ClientConfig{} },
			want: "",
		},
		{
			name: "literal secret",
			cfg:  func(*testing.T) ClientConfig { return ClientConfig{ClientSecret: *util.NewMaskedString("literal")} },
			want: "literal",
		},
		{
			name: "file secret is trimmed",
			cfg: func(t *testing.T) ClientConfig {
				t.Helper()
				return ClientConfig{ClientSecretFile: writeSecretFile(t, "  from-file\n")}
			},
			want: "from-file",
		},
		{
			name: "both set",
			cfg: func(t *testing.T) ClientConfig {
				t.Helper()
				return ClientConfig{
					ClientSecret:     *util.NewMaskedString("literal"),
					ClientSecretFile: writeSecretFile(t, "from-file"),
				}
			},
			wantErr: ErrClientSecretConflict.Error(),
		},
		{
			name: "file missing",
			cfg: func(t *testing.T) ClientConfig {
				t.Helper()
				return ClientConfig{ClientSecretFile: filepath.Join(t.TempDir(), "absent")}
			},
			wantErr: "client-secret-file",
		},
		{
			name: "file empty",
			cfg: func(t *testing.T) ClientConfig {
				t.Helper()
				return ClientConfig{ClientSecretFile: writeSecretFile(t, " \n")}
			},
			wantErr: "client-secret-file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := tt.cfg(t)

			got, err := cfg.ResolveClientSecret()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClientConfig_Validate_DoesNotReadSecretFile(t *testing.T) {
	t.Parallel()

	cfg := ClientConfig{ClientSecretFile: filepath.Join(t.TempDir(), "not-mounted-here")}

	assert.NoError(t, cfg.Validate())
}

func TestNewTokenSourceFromConfig_ClientSecretFileErrors(t *testing.T) {
	t.Parallel()

	base := ClientConfig{
		URL:              "https://issuer.example.com",
		ClientID:         "id",
		ClientSecretFile: filepath.Join(t.TempDir(), "absent"),
	}

	t.Run("unreadable file names the setting", func(t *testing.T) {
		t.Parallel()
		_, err := NewTokenSourceFromConfig(base)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client-secret-file")
	})

	t.Run("both settings rejected", func(t *testing.T) {
		t.Parallel()
		cfg := base
		cfg.ClientSecret = *util.NewMaskedString("literal")
		_, err := NewTokenSourceFromConfig(cfg)
		require.ErrorIs(t, err, ErrClientSecretConflict)
	})
}

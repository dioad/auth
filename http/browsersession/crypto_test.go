package browsersession

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKeyBytes(t *testing.T) []byte {
	t.Helper()

	key, err := parseKey(strings.Repeat("ab", keySize))
	require.NoError(t, err)
	return key
}

func TestParseKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{name: "64 hex characters", key: strings.Repeat("0f", 32)},
		{name: "empty", key: "", wantErr: true},
		{name: "not hex", key: strings.Repeat("zz", 32), wantErr: true},
		{name: "AES-128 length", key: strings.Repeat("0f", 16), wantErr: true},
		{name: "too long", key: strings.Repeat("0f", 33), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key, err := parseKey(tt.key)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.key, hex.EncodeToString(key))
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	t.Parallel()

	key := testKeyBytes(t)

	encrypted, err := encrypt(key, []byte("access-token"), "bff_session")
	require.NoError(t, err)
	assert.NotContains(t, encrypted, "access-token")

	again, err := encrypt(key, []byte("access-token"), "bff_session")
	require.NoError(t, err)
	assert.NotEqual(t, encrypted, again, "each encryption must use a fresh nonce")

	decrypted, err := decrypt(key, encrypted, "bff_session")
	require.NoError(t, err)
	assert.Equal(t, "access-token", string(decrypted))
}

func TestDecrypt_Rejects(t *testing.T) {
	t.Parallel()

	key := testKeyBytes(t)
	otherKey, err := parseKey(strings.Repeat("cd", keySize))
	require.NoError(t, err)

	encrypted, err := encrypt(key, []byte("access-token"), "bff_session")
	require.NoError(t, err)

	// Flip one character in the middle of the ciphertext.
	tampered := []byte(encrypted)
	mid := len(tampered) / 2
	if tampered[mid] == 'A' {
		tampered[mid] = 'B'
	} else {
		tampered[mid] = 'A'
	}

	tests := []struct {
		name    string
		key     []byte
		value   string
		purpose string
	}{
		{name: "another key", key: otherKey, value: encrypted, purpose: "bff_session"},
		{name: "another purpose", key: key, value: encrypted, purpose: "bff_refresh"},
		{name: "tampered ciphertext", key: key, value: string(tampered), purpose: "bff_session"},
		{name: "not base64url", key: key, value: "not base64!", purpose: "bff_session"},
		{name: "shorter than a nonce", key: key, value: "AAAA", purpose: "bff_session"},
		{name: "empty", key: key, value: "", purpose: "bff_session"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := decrypt(tt.key, tt.value, tt.purpose)
			require.Error(t, err)
		})
	}
}

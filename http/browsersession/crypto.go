package browsersession

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// keySize is the length in bytes of a cookie encryption key: AES-256.
const keySize = 32

// parseKey decodes a cookie encryption key: 64 hexadecimal characters.
func parseKey(keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid cookie encryption key: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("invalid cookie encryption key: want %d hex characters, got %d", keySize*2, len(keyHex))
	}
	return key, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// encrypt seals plaintext with AES-GCM and returns it base64url encoded.
// purpose is authenticated but not encrypted: a value sealed for one purpose
// does not open for another.
func encrypt(key, plaintext []byte, purpose string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	sealed := gcm.Seal(nonce, nonce, plaintext, []byte(purpose))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// decrypt opens a value sealed by encrypt for the same purpose.
func decrypt(key []byte, encoded, purpose string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(sealed) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := sealed[:nonceSize], sealed[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, []byte(purpose))
}

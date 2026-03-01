// Package hmac provides HMAC-based authentication middleware.
//
// This implementation follows the principles of HTTP Message Signatures (RFC 9421),
// providing a robust way to authenticate requests using a shared secret.
// It includes protection against:
// - Tampering: The HTTP method, path, query parameters, timestamp, principal, and selected headers are signed.
// - Replay Attacks: A mandatory timestamp is included in the signature and verified by the server.
// - Principal Spoofing: The principal ID is included in the signature.
// - Request Binding: Arbitrary headers (like access tokens) can be included in the signature.
package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultTimestampHeader is the default header used for the request timestamp.
	// This aligns with custom implementations; RFC 9421 uses the 'created' parameter.
	DefaultTimestampHeader = "X-Timestamp"
	// DefaultSignedHeadersHeader is the header used to list which headers are signed.
	// This aligns with custom implementations; RFC 9421 uses 'Signature-Input'.
	DefaultSignedHeadersHeader = "X-Signed-Headers"
	// AuthScheme is the scheme used in the Authorization header.
	AuthScheme                 = "HMAC"
	DefaultMaxRequestSizeBytes = 10 * 1024 * 1024 // 10 MB
	DefaultMaxTimestampDiff    = 5 * time.Minute
)

// CanonicalData generates the string to be signed based on the request.
// It follows a strict format to ensure both client and server produce the same string:
// 1. HTTP Method (e.g., POST)
// 2. HTTP Path with query parameters (e.g., /api/data?id=123)
// 3. Timestamp (decimal string)
// 4. Principal ID
// 5. Comma-separated list of signed header names
// 6. Each signed header as "name:value" (header values are trimmed of leading/trailing whitespace)
// 7. Request body
func CanonicalData(r *http.Request, principal string, timestamp string, signedHeaders []string, body []byte) string {
	var b strings.Builder

	// Method and Path with query parameters
	b.WriteString(r.Method)
	b.WriteString("\n")
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	b.WriteString(path)
	// Include query parameters in the signature to prevent tampering
	if r.URL.RawQuery != "" {
		b.WriteString("?")
		b.WriteString(r.URL.RawQuery)
	}
	b.WriteString("\n")

	// Timestamp
	b.WriteString(timestamp)
	b.WriteString("\n")

	// Principal
	b.WriteString(principal)
	b.WriteString("\n")

	// Signed Header names - normalize to lowercase for consistency
	normalizedHeaders := make([]string, len(signedHeaders))
	for i, h := range signedHeaders {
		normalizedHeaders[i] = strings.ToLower(h)
	}
	b.WriteString(strings.Join(normalizedHeaders, ","))
	b.WriteString("\n")

	// Signed Header values
	for _, h := range signedHeaders {
		val := strings.TrimSpace(r.Header.Get(h))
		b.WriteString(strings.ToLower(h))
		b.WriteString(":")
		b.WriteString(val)
		b.WriteString("\n")
	}

	// Body
	b.Write(body)

	return b.String()
}

// HMACKeyBytes generates an HMAC-SHA256 signature as bytes using the shared key and data.
func HMACKeyBytes(sharedKey, data []byte) ([]byte, error) {
	h := hmac.New(sha256.New, sharedKey)
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// HMACKey generates an HMAC-SHA256 signature as a hex-encoded string.
func HMACKey(sharedKey, data []byte) (string, error) {
	keyBytes, err := HMACKeyBytes(sharedKey, data)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", keyBytes), nil
}

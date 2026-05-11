// Package hmac provides HMAC-based authentication middleware.
package hmac

import (
	"bytes"
	stdcontext "context"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	authhttp "github.com/dioad/auth/http/context"
)

// NewHandler creates a new HMAC authentication handler with the provided configuration.
func NewHandler(cfg ServerConfig) *Handler {
	if cfg.MaxTimestampDiff == 0 {
		cfg.MaxTimestampDiff = DefaultMaxTimestampDiff
	}
	if cfg.MaxFutureTimestampDiff == 0 {
		cfg.MaxFutureTimestampDiff = 30 * time.Second
	}
	if len(cfg.SharedKey) == 0 {
		panic("hmac: shared key must not be empty")
	}
	return &Handler{cfg: cfg}
}

// Handler implements HMAC-based authentication.
type Handler struct {
	cfg ServerConfig
}

func (a *Handler) maxRequestSizeBytes() int {
	if a.cfg.MaxRequestSize > 0 {
		return a.cfg.MaxRequestSize
	}
	return DefaultMaxRequestSizeBytes
}

// parseAuthHeader parses the Authorization header and extracts the principal and signature.
func parseAuthHeader(authHeader string) (principal, signature string, err error) {
	if authHeader == "" {
		return "", "", errors.New("missing auth header")
	}

	if !strings.HasPrefix(authHeader, AuthScheme+" ") {
		return "", "", errors.New("invalid auth scheme")
	}

	credentials := strings.TrimPrefix(authHeader, AuthScheme+" ")
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return "", "", errors.New("invalid authorization header format")
	}

	return parts[0], parts[1], nil
}

// readAndValidateBody reads the request body with size limits and restores it for the handler.
func readAndValidateBody(r *http.Request, maxSize int) ([]byte, error) {
	if r.Body == nil {
		return []byte{}, nil
	}

	maxSizeInt64 := int64(maxSize)
	limitedReader := &io.LimitedReader{R: r.Body, N: maxSizeInt64}
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	// Check if there is more data beyond the maximum allowed size.
	extraBuf := make([]byte, 1)
	n, err := r.Body.Read(extraBuf)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	if n > 0 {
		return nil, errors.New("request body exceeds maximum size limit")
	}

	// Restore body for handler to use
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	return bodyBytes, nil
}

// verifyHMACSignature generates the canonical data and verifies the HMAC signature.
func verifyHMACSignature(r *http.Request, principal, signature, timestampStr string, signedHeaders []string, bodyBytes, sharedKey []byte) error {
	// Reconstruct canonical data
	verificationData := CanonicalData(r, principal, timestampStr, signedHeaders, bodyBytes)

	// Verify HMAC token
	verificationKey, err := HMACKey(sharedKey, []byte(verificationData))
	if err != nil {
		return fmt.Errorf("failed to generate verification key: %w", err)
	}

	// Use constant-time comparison to prevent timing attacks
	if !hmac.Equal([]byte(signature), []byte(verificationKey)) {
		return errors.New("invalid auth token")
	}

	return nil
}

// AuthRequest authenticates an HTTP request using HMAC.
// It expects an Authorization header in the format "HMAC principal:signature".
// It also verifies the request timestamp to prevent replay attacks.
func (a *Handler) AuthRequest(r *http.Request) (stdcontext.Context, error) {
	// Parse Authorization header
	principal, signature, err := parseAuthHeader(r.Header.Get("Authorization"))
	if err != nil {
		return r.Context(), err
	}

	// Verify timestamp
	timestampStr, err := verifyTimestamp(r, a.cfg.TimestampHeader, a.cfg.MaxTimestampDiff, a.cfg.MaxFutureTimestampDiff)
	if err != nil {
		return r.Context(), err
	}

	// Get signed headers
	signedHeaders, err := validateSignedHeaders(r, a.cfg.SignedHeaders)
	if err != nil {
		return r.Context(), err
	}

	// Read and validate request body
	bodyBytes, err := readAndValidateBody(r, a.maxRequestSizeBytes())
	if err != nil {
		return r.Context(), err
	}

	// Verify HMAC signature
	if err := verifyHMACSignature(r, principal, signature, timestampStr, signedHeaders, bodyBytes, []byte(a.cfg.SharedKey)); err != nil {
		return r.Context(), err
	}

	ctx := authhttp.ContextWithAuthenticatedPrincipal(r.Context(), principal)
	return ctx, nil
}

func validateSignedHeaders(r *http.Request, configuredSignedHeaders []string) ([]string, error) {
	signedHeadersStr := r.Header.Get(DefaultSignedHeadersHeader)
	var signedHeaders []string
	if signedHeadersStr != "" {
		signedHeaders = strings.Split(signedHeadersStr, ",")
	}
	// Validate signed headers against server configuration, if configured.
	if len(configuredSignedHeaders) > 0 {
		if len(signedHeaders) == 0 {
			return nil, errors.New("missing signed headers")
		}
		if len(signedHeaders) != len(configuredSignedHeaders) {
			return nil, errors.New("signed headers do not match server configuration")
		}
		for i, requiredHeader := range configuredSignedHeaders {
			clientHeader := signedHeaders[i]
			if !strings.EqualFold(strings.TrimSpace(requiredHeader), strings.TrimSpace(clientHeader)) {
				return nil, errors.New("signed headers do not match server configuration")
			}
		}
	}
	return signedHeaders, nil
}

// verifyTimestamp checks the timestamp header in the request to ensure it is within the allowed time window.
func verifyTimestamp(r *http.Request, timestampHeader string, maxTimestampDiff, maxFutureTimestampDiff time.Duration) (string, error) {
	if timestampHeader == "" {
		timestampHeader = DefaultTimestampHeader
	}

	timestampStr := r.Header.Get(timestampHeader)
	if timestampStr == "" {
		return "", fmt.Errorf("missing timestamp header: %s", timestampHeader)
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return "", errors.New("invalid timestamp format")
	}

	now := time.Now().Unix()
	diff := now - timestamp

	// Reject timestamps too far in the past
	if diff > int64(maxTimestampDiff.Seconds()) {
		return "", errors.New("request timestamp expired")
	}

	// Reject timestamps too far in the future
	// Use a smaller window to prevent pre-signed replay attacks
	maxFuture := int64(maxFutureTimestampDiff.Seconds())
	if diff < -maxFuture {
		return "", errors.New("request timestamp too far in the future")
	}
	return timestampStr, nil
}

func (a *Handler) Wrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := a.AuthRequest(r)

		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

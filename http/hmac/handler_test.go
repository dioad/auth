package hmac

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTimestampValidation_FutureTimestamps tests that future timestamps
// within the clock skew window are accepted, but far-future timestamps are rejected.
func TestTimestampValidation_FutureTimestamps(t *testing.T) {
	const sharedKey = "test-secret-key"
	const principal = "test-user"

	tests := []struct {
		name                   string
		maxTimestampDiff       time.Duration
		maxFutureTimestampDiff time.Duration
		timestampOffset        time.Duration // offset from current time (negative = past, positive = future)
		wantAccepted           bool
		wantErrorContains      string
	}{
		{
			name:                   "slightly future timestamp within clock skew",
			maxTimestampDiff:       5 * time.Minute,
			maxFutureTimestampDiff: 30 * time.Second,
			timestampOffset:        15 * time.Second, // 15 seconds in future
			wantAccepted:           true,
		},
		{
			name:                   "future timestamp at exact clock skew limit",
			maxTimestampDiff:       5 * time.Minute,
			maxFutureTimestampDiff: 30 * time.Second,
			timestampOffset:        30 * time.Second, // exactly 30 seconds in future
			wantAccepted:           true,
		},
		{
			name:                   "future timestamp at limit + 1",
			maxTimestampDiff:       5 * time.Minute,
			maxFutureTimestampDiff: 30 * time.Second,
			timestampOffset:        31 * time.Second, // exactly 31 seconds in future
			wantAccepted:           false,
			wantErrorContains:      "too far in the future",
		},
		{
			name:                   "far future timestamp exceeds clock skew",
			maxTimestampDiff:       5 * time.Minute,
			maxFutureTimestampDiff: 30 * time.Second,
			timestampOffset:        2 * time.Minute, // 2 minutes in future
			wantAccepted:           false,
			wantErrorContains:      "too far in the future",
		},
		{
			name:                   "far future timestamp at MaxTimestampDiff",
			maxTimestampDiff:       5 * time.Minute,
			maxFutureTimestampDiff: 30 * time.Second,
			timestampOffset:        5 * time.Minute, // 5 minutes in future
			wantAccepted:           false,
			wantErrorContains:      "too far in the future",
		},
		{
			name:                   "current timestamp",
			maxTimestampDiff:       5 * time.Minute,
			maxFutureTimestampDiff: 30 * time.Second,
			timestampOffset:        0,
			wantAccepted:           true,
		},
		{
			name:                   "recent past timestamp within MaxTimestampDiff",
			maxTimestampDiff:       5 * time.Minute,
			maxFutureTimestampDiff: 30 * time.Second,
			timestampOffset:        -2 * time.Minute, // 2 minutes ago
			wantAccepted:           true,
		},
		{
			name:                   "old past timestamp at MaxTimestampDiff limit",
			maxTimestampDiff:       5 * time.Minute,
			maxFutureTimestampDiff: 30 * time.Second,
			timestampOffset:        -5 * time.Minute, // exactly 5 minutes ago
			wantAccepted:           true,
		},
		{
			name:                   "old past timestamp exceeds MaxTimestampDiff",
			maxTimestampDiff:       5 * time.Minute,
			maxFutureTimestampDiff: 30 * time.Second,
			timestampOffset:        -6 * time.Minute, // 6 minutes ago
			wantAccepted:           false,
			wantErrorContains:      "expired",
		},
		{
			name:                   "custom MaxFutureTimestampDiff - accept within limit",
			maxTimestampDiff:       5 * time.Minute,
			maxFutureTimestampDiff: 1 * time.Minute,
			timestampOffset:        45 * time.Second, // 45 seconds in future
			wantAccepted:           true,
		},
		{
			name:                   "custom MaxFutureTimestampDiff - reject beyond limit",
			maxTimestampDiff:       5 * time.Minute,
			maxFutureTimestampDiff: 1 * time.Minute,
			timestampOffset:        90 * time.Second, // 90 seconds in future
			wantAccepted:           false,
			wantErrorContains:      "too far in the future",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler with custom config
			handler := NewHandler(ServerConfig{
				CommonConfig: CommonConfig{
					SharedKey: sharedKey,
				},
				MaxTimestampDiff:       tt.maxTimestampDiff,
				MaxFutureTimestampDiff: tt.maxFutureTimestampDiff,
			})

			// Calculate timestamp with offset
			timestamp := time.Now().Unix() + int64(tt.timestampOffset.Seconds())
			timestampStr := fmt.Sprintf("%d", timestamp)

			// Create test request with manually crafted headers
			req := httptest.NewRequest("GET", "http://example.com/test", nil)

			// Create client auth to generate valid signature
			clientAuth := ClientAuth{
				Config: ClientConfig{
					CommonConfig: CommonConfig{
						SharedKey: sharedKey,
					},
					Principal: principal,
				},
			}

			// Add auth which will set current timestamp
			require.NoError(t, clientAuth.AddAuth(req), "failed to add auth")

			// Override the timestamp header with our test timestamp
			req.Header.Set(DefaultTimestampHeader, timestampStr)

			// Regenerate signature with the modified timestamp
			bodyBytes := []byte{}
			signedHeaders := []string{}
			verificationData := CanonicalData(req, principal, timestampStr, signedHeaders, bodyBytes)
			signature, err := HMACKey([]byte(sharedKey), []byte(verificationData))
			require.NoError(t, err, "failed to generate signature")
			req.Header.Set("Authorization", fmt.Sprintf("HMAC %s:%s", principal, signature))

			// Test authentication
			ctx, err := handler.AuthRequest(req)

			if tt.wantAccepted {
				assert.NoError(t, err, "expected request to be accepted")
				assert.NotNil(t, ctx)
			} else {
				if assert.Error(t, err, "expected request to be rejected, but it was accepted") && tt.wantErrorContains != "" {
					assert.Contains(t, err.Error(), tt.wantErrorContains)
				}
			}
		})
	}
}

// TestTimestampValidation_DefaultConfig tests that the default configuration works correctly.
func TestTimestampValidation_DefaultConfig(t *testing.T) {
	const sharedKey = "test-key"

	handler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{
			SharedKey: sharedKey,
		},
	})

	// Verify defaults were set
	assert.Equal(t, 5*time.Minute, handler.cfg.MaxTimestampDiff)
	assert.Equal(t, 30*time.Second, handler.cfg.MaxFutureTimestampDiff)
}

// TestTimestampValidation_PreSignedReplayAttackPrevention tests that the fix
// prevents the pre-signed replay attack described in the issue.
func TestTimestampValidation_PreSignedReplayAttackPrevention(t *testing.T) {
	const sharedKey = "test-secret"
	const principal = "attacker"

	handler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{
			SharedKey: sharedKey,
		},
		MaxTimestampDiff:       5 * time.Minute,
		MaxFutureTimestampDiff: 30 * time.Second,
	})

	// Simulate the attack scenario from the issue:
	// Attacker creates a request with timestamp 5 minutes in the future
	futureTimestamp := time.Now().Unix() + int64(5*time.Minute.Seconds())
	timestampStr := fmt.Sprintf("%d", futureTimestamp)

	req := httptest.NewRequest("GET", "http://example.com/api", nil)

	clientAuth := ClientAuth{
		Config: ClientConfig{
			CommonConfig: CommonConfig{SharedKey: sharedKey},
			Principal:    principal,
		},
	}

	require.NoError(t, clientAuth.AddAuth(req), "failed to add auth")

	// Override with future timestamp and regenerate signature
	req.Header.Set(DefaultTimestampHeader, timestampStr)
	bodyBytes := []byte{}
	signedHeaders := []string{}
	verificationData := CanonicalData(req, principal, timestampStr, signedHeaders, bodyBytes)
	signature, err := HMACKey([]byte(sharedKey), []byte(verificationData))
	require.NoError(t, err, "failed to generate signature")
	req.Header.Set("Authorization", fmt.Sprintf("HMAC %s:%s", principal, signature))

	// This request should be rejected because the timestamp is too far in the future
	_, err = handler.AuthRequest(req)
	if assert.Error(t, err, "expected pre-signed request with far-future timestamp to be rejected") {
		assert.Contains(t, err.Error(), "too far in the future")
	}
}

const (
	// expectedMaxSizeErrorMessage is the expected error message when request size limit is exceeded
	expectedMaxSizeErrorMessage = "exceeds maximum size limit"
)

// createAuthenticatedRequest is a helper function to create an authenticated request with a body of specified size.
func createAuthenticatedRequest(t *testing.T, sharedKey, principal string, bodySize int) *http.Request {
	t.Helper()

	bodyContent := strings.Repeat("a", bodySize)
	req := httptest.NewRequest("POST", "http://example.com/api", strings.NewReader(bodyContent))

	clientAuth := ClientAuth{
		Config: ClientConfig{
			CommonConfig: CommonConfig{SharedKey: sharedKey},
			Principal:    principal,
		},
	}

	require.NoError(t, clientAuth.AddAuth(req), "failed to add auth")

	return req
}

// TestMaxRequestSize_UnderLimit tests that requests under the size limit are accepted.
func TestMaxRequestSize_UnderLimit(t *testing.T) {
	const sharedKey = "test-key"
	const principal = "user"
	const maxSize = 1024 // 1KB limit

	handler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{
			SharedKey: sharedKey,
		},
		MaxRequestSize: maxSize,
	})

	// Create a request with body under the limit (500 bytes)
	req := createAuthenticatedRequest(t, sharedKey, principal, 500)

	// Request should be accepted
	ctx, err := handler.AuthRequest(req)
	assert.NoError(t, err, "expected request under size limit to be accepted")
	assert.NotNil(t, ctx)
}

// TestMaxRequestSize_ExceedsLimit tests that requests exceeding the size limit are rejected.
func TestMaxRequestSize_ExceedsLimit(t *testing.T) {
	const sharedKey = "test-key"
	const principal = "user"
	const maxSize = 1024 // 1KB limit

	handler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{
			SharedKey: sharedKey,
		},
		MaxRequestSize: maxSize,
	})

	// Create a request with body exceeding the limit (2KB)
	req := createAuthenticatedRequest(t, sharedKey, principal, 2048)

	// Request should be rejected
	_, err := handler.AuthRequest(req)
	if assert.Error(t, err, "expected request exceeding size limit to be rejected") {
		assert.Contains(t, err.Error(), expectedMaxSizeErrorMessage)
	}
}

// TestMaxRequestSize_DefaultLimit tests that the default 10MB limit is applied when not configured.
func TestMaxRequestSize_DefaultLimit(t *testing.T) {
	const sharedKey = "test-key"
	const principal = "user"

	handler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{
			SharedKey: sharedKey,
		},
		// MaxRequestSize not set - should use default
	})

	// Verify the default limit is applied
	assert.Equal(t, DefaultMaxRequestSizeBytes, handler.maxRequestSizeBytes())

	// Create a request with body under the default limit (9MB - close to the 10MB default)
	bodySize := 9 * 1024 * 1024 // 9MB
	req := createAuthenticatedRequest(t, sharedKey, principal, bodySize)

	// Request should be accepted with default limit
	ctx, err := handler.AuthRequest(req)
	assert.NoError(t, err, "expected request under default limit to be accepted")
	assert.NotNil(t, ctx)
}

// TestMaxRequestSize_AtExactLimit tests behavior at the exact size limit.
func TestMaxRequestSize_AtExactLimit(t *testing.T) {
	const sharedKey = "test-key"
	const principal = "user"
	const maxSize = 1024 // 1KB limit

	handler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{
			SharedKey: sharedKey,
		},
		MaxRequestSize: maxSize,
	})

	// Create a request with body exactly at the limit (1024 bytes)
	req := createAuthenticatedRequest(t, sharedKey, principal, maxSize)

	// Request at exact limit should be accepted
	ctx, err := handler.AuthRequest(req)
	assert.NoError(t, err, "expected request at exact limit to be accepted")
	assert.NotNil(t, ctx)
}

// TestMaxRequestSize_OneBytePastLimit tests behavior one byte past the limit.
func TestMaxRequestSize_OneBytePastLimit(t *testing.T) {
	const sharedKey = "test-key"
	const principal = "user"
	const maxSize = 1024 // 1KB limit

	handler := NewHandler(ServerConfig{
		CommonConfig: CommonConfig{
			SharedKey: sharedKey,
		},
		MaxRequestSize: maxSize,
	})

	// Create a request with body one byte over the limit (1025 bytes)
	req := createAuthenticatedRequest(t, sharedKey, principal, maxSize+1)

	// Request should be rejected
	_, err := handler.AuthRequest(req)
	if assert.Error(t, err, "expected request one byte over limit to be rejected") {
		assert.Contains(t, err.Error(), expectedMaxSizeErrorMessage)
	}
}

package hmac

import "time"

// CommonConfig contains shared configuration for HMAC authentication.
type CommonConfig struct {
	AllowInsecureHTTP bool `mapstructure:"allow-insecure-http"`
	// Inline shared key used to HMAC with value from HTTPHeader
	SharedKey string `mapstructure:"shared-key"`
	// HTTP Headers to include in the HMAC calculation.
	SignedHeaders []string `mapstructure:"signed-headers"`
	// HTTP Header to use for the timestamp (default: X-Timestamp)
	TimestampHeader string `mapstructure:"timestamp-header"`
}

// ClientConfig contains configuration for an HMAC authentication client.
type ClientConfig struct {
	CommonConfig `mapstructure:",squash"`
	// Principal ID to use for authentication
	Principal string `mapstructure:"principal"`
}

// ServerConfig contains configuration for an HMAC authentication server.
type ServerConfig struct {
	CommonConfig `mapstructure:",squash"`
	// Maximum allowed time difference for the timestamp (default: 5m)
	MaxTimestampDiff time.Duration `mapstructure:"max-timestamp-diff"`
	// Maximum allowed time difference for future timestamps (default: 30s)
	// This should be smaller than MaxTimestampDiff to prevent pre-signed replay attacks.
	// A smaller value is appropriate since it only needs to account for clock skew.
	MaxFutureTimestampDiff time.Duration `mapstructure:"max-future-timestamp-diff"`
	// Maximum request size in bytes (default: 10 MB)
	MaxRequestSize int `mapstructure:"max-request-size"`
}

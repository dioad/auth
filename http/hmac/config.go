package hmac

import "time"

// CommonConfig contains shared configuration for HMAC authentication.
type CommonConfig struct {
	AllowInsecureHTTP bool `mapstructure:"allow-insecure-http" desc:"allow HMAC authentication over plain HTTP, for local development only"`
	// Inline shared key used to HMAC with value from HTTPHeader
	SharedKey string `mapstructure:"shared-key" desc:"shared key used to compute the HMAC"`
	// HTTP Headers to include in the HMAC calculation.
	SignedHeaders []string `mapstructure:"signed-headers" desc:"HTTP headers to include in the HMAC calculation"`
	// HTTP Header to use for the timestamp (default: X-Timestamp)
	TimestampHeader string `mapstructure:"timestamp-header" desc:"HTTP header carrying the request timestamp"`
}

// ClientConfig contains configuration for an HMAC authentication client.
type ClientConfig struct {
	CommonConfig `mapstructure:",squash"`

	// Principal ID to use for authentication
	Principal string `mapstructure:"principal" desc:"principal ID to authenticate as"`
}

// ServerConfig contains configuration for an HMAC authentication server.
type ServerConfig struct {
	CommonConfig `mapstructure:",squash"`

	// Maximum allowed time difference for the timestamp (default: 5m)
	MaxTimestampDiff time.Duration `mapstructure:"max-timestamp-diff" desc:"maximum age of a request timestamp"`
	// Maximum allowed time difference for future timestamps (default: 30s)
	// This should be smaller than MaxTimestampDiff to prevent pre-signed replay attacks.
	// A smaller value is appropriate since it only needs to account for clock skew.
	MaxFutureTimestampDiff time.Duration `mapstructure:"max-future-timestamp-diff" desc:"maximum amount a request timestamp may be in the future, to allow for clock skew; keep it below the maximum age"`
	// Maximum request size in bytes (default: 10 MB)
	MaxRequestSize int `mapstructure:"max-request-size" desc:"maximum request size in bytes"`
}

package server

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"github.com/dioad/auth"
	"github.com/dioad/auth/authctx"
	"github.com/dioad/config/configcheck"
	nethttp "github.com/dioad/net/http"
)

const (
	// DefaultRateLimitRPS is the per-principal request rate applied when
	// RateLimitConfig.RPS is zero.
	DefaultRateLimitRPS = 10000.0
	// DefaultRateLimitBurst is the per-principal burst applied when
	// RateLimitConfig.Burst is zero.
	DefaultRateLimitBurst = 1000
)

// RateLimitConfig configures the per-principal request rate limiter built by
// RateLimiter. It is meant to be squashed into a service config so the keys
// stay flat (rate-limit-rps and so on).
type RateLimitConfig struct {
	// RPS is the sustained per-principal request rate. Zero selects
	// DefaultRateLimitRPS.
	RPS float64 `desc:"sustained per-principal request rate; 0 selects the default" mapstructure:"rate-limit-rps"`
	// Burst is the per-principal burst size. Zero selects
	// DefaultRateLimitBurst.
	Burst int `desc:"per-principal burst size; 0 selects the default" mapstructure:"rate-limit-burst"`
	// Disable turns the limiter off.
	Disable bool `desc:"turn the rate limiter off" mapstructure:"disable-rate-limit"`
}

// Check reports a negative limit to findings, which should be positioned where
// the config's keys are read from: the root of the service config it is
// squashed into. A disabled limiter has nothing to report.
func (c RateLimitConfig) Check(findings *configcheck.Collector) {
	if c.Disable {
		return
	}
	if c.RPS < 0 {
		findings.Field("rate-limit-rps").Errorf("cannot be negative")
	}
	if c.Burst < 0 {
		findings.Field("rate-limit-burst").Errorf("cannot be negative")
	}
}

// RateLimitOption configures RateLimiter.
type RateLimitOption func(*rateLimitOptions)

type rateLimitOptions struct {
	resolver *nethttp.ClientIPResolver
}

// WithClientIPResolver sets how the limiter finds the client address it keys
// an unauthenticated request by. Use it for a service behind a proxy, where
// the connection's own address is the proxy's and every unauthenticated
// caller would otherwise share one bucket. Without it the key is the
// connection's address.
func WithClientIPResolver(resolver *nethttp.ClientIPResolver) RateLimitOption {
	return func(o *rateLimitOptions) { o.resolver = resolver }
}

// PrincipalKey returns the rate limit key of a request: the ID of the
// principal extracted by the principal extraction middleware, else the
// subject of the validated token, else the address of the connection the
// request arrived on. It never reads a forwarding header, so a caller cannot
// choose its key. Use PrincipalKeyFunc for a service behind a proxy.
func PrincipalKey(r *http.Request) (string, error) {
	return principalKey(r, connectionAddress)
}

// PrincipalKeyFunc returns a key function like PrincipalKey that falls back
// to the client address resolver finds, so only the proxies and headers the
// resolver trusts can say what that address is. A nil resolver selects the
// address of the connection.
func PrincipalKeyFunc(resolver *nethttp.ClientIPResolver) nethttp.PrincipalFunc {
	if resolver == nil {
		return PrincipalKey
	}
	return func(r *http.Request) (string, error) {
		return principalKey(r, resolver)
	}
}

// connectionAddress trusts no header: it resolves the address of the
// connection only.
var connectionAddress = nethttp.NewClientIPResolver()

func principalKey(r *http.Request, resolver *nethttp.ClientIPResolver) (string, error) {
	ctx := r.Context()
	if pc := auth.PrincipalContextFromContext(ctx); pc != nil && pc.ID != "" {
		return pc.ID, nil
	}
	if subject, ok := authctx.AuthenticatedPrincipalFromContext(ctx); ok && subject != "" {
		return subject, nil
	}
	return resolver.ClientIP(r), nil
}

// RateLimiter returns a middleware that limits each principal to the request
// rate in cfg, keyed by PrincipalKey, or a pass-through when cfg disables the
// limiter. It logs to logger and registers its metrics with registerer; a nil
// registerer selects the default one, which only one limiter in a process can
// usefully share.
//
// It must run after token validation and principal extraction, so place it
// after the result of APIMiddlewares. Ahead of them no request has a
// principal yet, and every caller is keyed by address instead.
//
// The limiter keeps a background cleanup task for as long as the process
// runs, so build one per server rather than one per request or route.
func RateLimiter(cfg RateLimitConfig, logger zerolog.Logger, registerer prometheus.Registerer, opts ...RateLimitOption) (nethttp.Middleware, error) {
	findings := configcheck.NewCollector()
	cfg.Check(findings)
	if err := findings.Err(); err != nil {
		return nil, fmt.Errorf("invalid rate limit config: %w", err)
	}
	if cfg.Disable {
		return func(next http.Handler) http.Handler { return next }, nil
	}

	var options rateLimitOptions
	for _, opt := range opts {
		opt(&options)
	}

	rps, burst := cfg.RPS, cfg.Burst
	if rps == 0 {
		rps = DefaultRateLimitRPS
	}
	if burst == 0 {
		burst = DefaultRateLimitBurst
	}

	limiterOpts := []nethttp.RateLimiterOption{
		nethttp.WithStaticRateLimit(rps, burst),
		nethttp.WithPrincipalFunc(PrincipalKeyFunc(options.resolver)),
		nethttp.WithRateLimitLogger(logger),
	}
	if registerer != nil {
		limiterOpts = append(limiterOpts, nethttp.WithRateLimiterRegistry(registerer))
	}
	return nethttp.NewRateLimiter(limiterOpts...).Middleware, nil
}

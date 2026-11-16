package server_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth"
	"github.com/dioad/auth/authctx"
	"github.com/dioad/auth/http/server"
	"github.com/dioad/config/configcheck"
	nethttp "github.com/dioad/net/http"
)

const rateLimitMetric = "dioad_net_http_rate_limit_requests_total"

// oneRequestLimiter admits a single request per key before refusing.
func oneRequestLimiter(t *testing.T, opts ...server.RateLimitOption) nethttp.Middleware {
	t.Helper()
	limiter, err := server.RateLimiter(server.RateLimitConfig{RPS: 0.001, Burst: 1}, zerolog.Nop(), prometheus.NewRegistry(), opts...)
	require.NoError(t, err)
	return limiter
}

func requestFrom(t *testing.T, remoteAddr string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	return r
}

func asPrincipal(r *http.Request, id string) *http.Request {
	return r.WithContext(auth.ContextWithPrincipalContext(r.Context(), &auth.PrincipalContext{ID: id}))
}

func TestPrincipalKey(t *testing.T) {
	t.Parallel()

	withSubject := func(r *http.Request, subject string) *http.Request {
		return r.WithContext(authctx.ContextWithAuthenticatedPrincipal(r.Context(), subject))
	}

	tests := []struct {
		name    string
		request func(r *http.Request) *http.Request
		want    string
	}{
		{
			name:    "the extracted principal comes first",
			request: func(r *http.Request) *http.Request { return asPrincipal(withSubject(r, "token-subject"), "alice") },
			want:    "alice",
		},
		{
			name:    "the token subject stands in for a missing principal",
			request: func(r *http.Request) *http.Request { return withSubject(r, "token-subject") },
			want:    "token-subject",
		},
		{
			name:    "a principal without an ID falls back to the token subject",
			request: func(r *http.Request) *http.Request { return asPrincipal(withSubject(r, "token-subject"), "") },
			want:    "token-subject",
		},
		{
			name:    "an unauthenticated request is keyed by the connection address",
			request: func(r *http.Request) *http.Request { return r },
			want:    "192.0.2.1",
		},
		{
			name: "forwarding headers do not choose the key",
			request: func(r *http.Request) *http.Request {
				r.Header.Set("X-Forwarded-For", "198.51.100.7")
				r.Header.Set("Forwarded", "for=198.51.100.7")
				r.Header.Set("X-Real-IP", "198.51.100.7")
				return r
			},
			want: "192.0.2.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key, err := server.PrincipalKey(tt.request(requestFrom(t, "192.0.2.1:4711")))

			require.NoError(t, err)
			assert.Equal(t, tt.want, key)
		})
	}
}

func TestPrincipalKeyFunc_HonoursOnlyTheResolversTrustedProxies(t *testing.T) {
	t.Parallel()

	key := server.PrincipalKeyFunc(nethttp.NewClientIPResolver(
		nethttp.WithTrustedProxyCIDRs(netip.MustParsePrefix("10.0.0.0/8")),
	))

	viaProxy := requestFrom(t, "10.0.0.1:4711")
	viaProxy.Header.Set("X-Forwarded-For", "198.51.100.7")
	got, err := key(viaProxy)
	require.NoError(t, err)
	assert.Equal(t, "198.51.100.7", got, "a trusted proxy names the client")

	direct := requestFrom(t, "192.0.2.1:4711")
	direct.Header.Set("X-Forwarded-For", "198.51.100.7")
	got, err = key(direct)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.1", got, "an untrusted peer cannot name itself")
}

func TestPrincipalKeyFunc_NilResolverUsesTheConnectionAddress(t *testing.T) {
	t.Parallel()

	r := requestFrom(t, "192.0.2.1:4711")
	r.Header.Set("X-Forwarded-For", "198.51.100.7")

	key, err := server.PrincipalKeyFunc(nil)(r)

	require.NoError(t, err)
	assert.Equal(t, "192.0.2.1", key)
}

func TestRateLimiter_PrincipalsHaveSeparateBuckets(t *testing.T) {
	t.Parallel()

	chain := []nethttp.Middleware{oneRequestLimiter(t)}
	from := func(id string) *http.Request { return asPrincipal(requestFrom(t, "192.0.2.1:4711"), id) }

	assert.Equal(t, http.StatusNoContent, serve(t, chain, from("alice")).Code)
	assert.Equal(t, http.StatusTooManyRequests, serve(t, chain, from("alice")).Code)
	assert.Equal(t, http.StatusNoContent, serve(t, chain, from("bob")).Code, "bob shares alice's address but not her bucket")
}

func TestRateLimiter_UnauthenticatedCallerCannotChooseItsBucket(t *testing.T) {
	t.Parallel()

	chain := []nethttp.Middleware{oneRequestLimiter(t)}
	claiming := func(remoteAddr, forwardedFor string) *http.Request {
		r := requestFrom(t, remoteAddr)
		r.Header.Set("X-Forwarded-For", forwardedFor)
		r.Header.Set("Forwarded", "for="+forwardedFor)
		r.Header.Set("X-Real-IP", forwardedFor)
		return r
	}

	assert.Equal(t, http.StatusNoContent, serve(t, chain, claiming("192.0.2.1:4711", "198.51.100.1")).Code)
	assert.Equal(t, http.StatusTooManyRequests, serve(t, chain, claiming("192.0.2.1:4712", "198.51.100.2")).Code,
		"rotating forwarding headers does not reset the limit")
	assert.Equal(t, http.StatusNoContent, serve(t, chain, claiming("192.0.2.2:4711", "198.51.100.1")).Code,
		"another connection address has its own bucket")
}

func TestRateLimiter_WithClientIPResolverKeysByTheResolvedAddress(t *testing.T) {
	t.Parallel()

	chain := []nethttp.Middleware{oneRequestLimiter(t, server.WithClientIPResolver(
		nethttp.NewClientIPResolver(nethttp.WithTrustedProxyCIDRs(netip.MustParsePrefix("10.0.0.0/8"))),
	))}
	viaProxy := func(client string) *http.Request {
		r := requestFrom(t, "10.0.0.1:4711")
		r.Header.Set("X-Forwarded-For", client)
		return r
	}

	assert.Equal(t, http.StatusNoContent, serve(t, chain, viaProxy("198.51.100.1")).Code)
	assert.Equal(t, http.StatusTooManyRequests, serve(t, chain, viaProxy("198.51.100.1")).Code)
	assert.Equal(t, http.StatusNoContent, serve(t, chain, viaProxy("198.51.100.2")).Code,
		"clients behind one trusted proxy do not share a bucket")
}

func TestRateLimiter_DisableIsAPassThrough(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	limiter, err := server.RateLimiter(server.RateLimitConfig{RPS: 0.001, Burst: 1, Disable: true}, zerolog.Nop(), registry)
	require.NoError(t, err)
	chain := []nethttp.Middleware{limiter}

	for range 3 {
		assert.Equal(t, http.StatusNoContent, serve(t, chain, requestFrom(t, "192.0.2.1:4711")).Code)
	}
	families, err := registry.Gather()
	require.NoError(t, err)
	assert.Empty(t, families, "a disabled limiter registers no metrics")
}

func TestRateLimiter_ZeroLimitsSelectTheDefaults(t *testing.T) {
	t.Parallel()

	limiter, err := server.RateLimiter(server.RateLimitConfig{}, zerolog.Nop(), prometheus.NewRegistry())
	require.NoError(t, err)
	chain := []nethttp.Middleware{limiter}

	for range server.DefaultRateLimitBurst {
		require.Equal(t, http.StatusNoContent, serve(t, chain, requestFrom(t, "192.0.2.1:4711")).Code)
	}
}

func TestRateLimiter_RegistersWithTheGivenRegistererOnly(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	limiter, err := server.RateLimiter(server.RateLimitConfig{}, zerolog.Nop(), registry)
	require.NoError(t, err)
	serve(t, []nethttp.Middleware{limiter}, requestFrom(t, "192.0.2.1:4711"))

	assert.Contains(t, metricNames(t, registry), rateLimitMetric)
	assert.NotContains(t, metricNames(t, prometheus.DefaultGatherer), rateLimitMetric)
}

func metricNames(t *testing.T, gatherer prometheus.Gatherer) []string {
	t.Helper()
	families, err := gatherer.Gather()
	require.NoError(t, err)
	names := make([]string, len(families))
	for i, family := range families {
		names[i] = family.GetName()
	}
	return names
}

func TestRateLimiter_RejectsNegativeLimits(t *testing.T) {
	t.Parallel()

	_, err := server.RateLimiter(server.RateLimitConfig{RPS: -1}, zerolog.Nop(), prometheus.NewRegistry())

	assert.ErrorContains(t, err, "rate-limit-rps: cannot be negative")
}

func TestRateLimitConfig_Check(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  server.RateLimitConfig
		want []configcheck.Finding
	}{
		{name: "zero selects the defaults", cfg: server.RateLimitConfig{}},
		{name: "positive limits", cfg: server.RateLimitConfig{RPS: 5, Burst: 10}},
		{
			name: "negative limits",
			cfg:  server.RateLimitConfig{RPS: -1, Burst: -1},
			want: []configcheck.Finding{
				{Path: "rate-limit-rps", Message: "cannot be negative"},
				{Path: "rate-limit-burst", Message: "cannot be negative"},
			},
		},
		{name: "a disabled limiter is not checked", cfg: server.RateLimitConfig{RPS: -1, Burst: -1, Disable: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := configcheck.NewCollector()
			tt.cfg.Check(findings)

			assert.Equal(t, tt.want, findings.Findings())
		})
	}
}

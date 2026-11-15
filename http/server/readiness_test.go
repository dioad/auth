package server_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/lifecycle"

	"github.com/dioad/auth/http/server"
	"github.com/dioad/auth/oidc"
)

// fakeIssuer serves an OIDC discovery document and a JWKS, counting discovery
// requests.
type fakeIssuer struct {
	*httptest.Server

	discoveries atomic.Int32
}

func newFakeIssuer(t *testing.T, jwks string) *fakeIssuer {
	t.Helper()
	idp := &fakeIssuer{}
	idp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			idp.discoveries.Add(1)
			_, _ = w.Write([]byte(`{"issuer":"` + idp.URL + `","jwks_uri":"` + idp.URL + `/jwks"}`))
		case "/jwks":
			_, _ = w.Write([]byte(jwks))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)

	return idp
}

// fakeClock is a settable clock for the readiness cache.
type fakeClock struct{ now atomic.Int64 }

func (c *fakeClock) Now() time.Time          { return time.Unix(0, c.now.Load()) }
func (c *fakeClock) Advance(d time.Duration) { c.now.Add(int64(d)) }

const oneKey = `{"keys":[{"kty":"RSA","kid":"k1"}]}`

// started returns a started Readiness with the validators' check added.
func started(validators []oidc.ValidatorConfig, readiness ...lifecycle.ReadinessOption) *lifecycle.Readiness {
	r := lifecycle.NewReadiness(readiness...)
	server.AddValidatorCheck(r, validators)
	r.MarkStarted()

	return r
}

// details returns the per-check report of r.Ready.
func details(t *testing.T, r *lifecycle.Readiness) map[string]string {
	t.Helper()
	report, err := r.Ready(t.Context())
	require.NoError(t, err, "an identity provider problem must not make the instance not-ready")
	checks, ok := report.(map[string]string)
	require.True(t, ok)

	return checks
}

func TestAddValidatorCheck_AddsNothingWithoutKeyFetchingValidators(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		validators []oidc.ValidatorConfig
	}{
		{"no validators", nil},
		{"only HMAC validators", []oidc.ValidatorConfig{{Issuer: "https://issuer.example", HMACSecret: "s3cr3t", AllowInsecureHMAC: true}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Empty(t, details(t, started(tc.validators)))
		})
	}
}

func TestAddValidatorCheck_ReportsTheIdentityProviderAsADegradedDependency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		jwks string
		want string
	}{
		{"keys served", oneKey, "ok"},
		{"empty key set", `{"keys":[]}`, "degraded: "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			idp := newFakeIssuer(t, tc.jwks)

			checks := details(t, started([]oidc.ValidatorConfig{{Issuer: idp.URL}}))

			assert.Contains(t, checks[server.ValidatorCheckName], tc.want)
		})
	}
}

func TestAddValidatorCheck_ProbesEachIssuerOnceAndReusesTheResult(t *testing.T) {
	t.Parallel()

	idp := newFakeIssuer(t, oneKey)
	clock := &fakeClock{}
	r := started([]oidc.ValidatorConfig{{Issuer: idp.URL}, {Issuer: idp.URL}}, lifecycle.WithClock(clock.Now))

	details(t, r)
	details(t, r)
	assert.Equal(t, int32(1), idp.discoveries.Load(), "validators sharing an issuer are probed once, and the result is cached")

	clock.Advance(server.DefaultValidatorCheckCacheTTL)
	details(t, r)
	assert.Equal(t, int32(2), idp.discoveries.Load(), "the issuer is probed again once the cached result expires")
}

func TestAddValidatorCheck_AHangingIssuerIsBoundedByTheCheckTimeout(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); hang.Close() })
	idp := newFakeIssuer(t, oneKey)
	r := started([]oidc.ValidatorConfig{{Issuer: hang.URL}, {Issuer: idp.URL}})

	start := time.Now()
	checks := details(t, r)

	assert.Less(t, time.Since(start), server.DefaultValidatorCheckTimeout+time.Second,
		"issuers are probed concurrently within one check timeout")
	assert.Contains(t, checks[server.ValidatorCheckName], "degraded: "+hang.URL)
	assert.NotContains(t, checks[server.ValidatorCheckName], idp.URL+":", "a hanging issuer must not use up the time the others need")
}

func TestAddValidatorCheck_OptionsReplaceTheDefaults(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); hang.Close() })
	r := lifecycle.NewReadiness()
	server.AddValidatorCheck(r, []oidc.ValidatorConfig{{Issuer: hang.URL}}, lifecycle.WithCheckTimeout(50*time.Millisecond))
	r.MarkStarted()

	start := time.Now()
	details(t, r)

	assert.Less(t, time.Since(start), time.Second, "a shorter timeout passed as an option must replace the default")
}

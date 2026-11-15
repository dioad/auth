package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

const oneKey = `{"keys":[{"kty":"RSA","kid":"k1"}]}`

func TestProbeValidators_PassesWithoutKeyFetchingValidators(t *testing.T) {
	t.Parallel()

	hmac := []oidc.ValidatorConfig{{Issuer: "https://issuer.example", HMACSecret: "s3cr3t", AllowInsecureHMAC: true}}

	assert.NoError(t, oidc.ProbeValidators(t.Context(), nil, nil))
	assert.NoError(t, oidc.ProbeValidators(t.Context(), hmac, nil))
	assert.Empty(t, oidc.KeyFetchingIssuers(hmac))
}

func TestProbeValidators_ProbesTheIssuerTheValidatorUses(t *testing.T) {
	t.Parallel()

	down := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(down.Close)

	tests := []struct {
		name      string
		validator func(up string) oidc.ValidatorConfig
		wantErr   bool
	}{
		{"issuer set", func(up string) oidc.ValidatorConfig { return oidc.ValidatorConfig{Issuer: up} }, false},
		{"issuer falls back to the endpoint URL", func(up string) oidc.ValidatorConfig { return oidc.ValidatorConfig{URL: up} }, false},
		{"issuer wins over the endpoint URL", func(up string) oidc.ValidatorConfig {
			return oidc.ValidatorConfig{Issuer: down.URL, URL: up}
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			idp := newFakeIssuer(t, oneKey)

			err := oidc.ProbeValidators(t.Context(), []oidc.ValidatorConfig{tc.validator(idp.URL)}, nil)

			if tc.wantErr {
				assert.ErrorContains(t, err, down.URL)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestProbeValidators_RejectsAnEmptyKeySet(t *testing.T) {
	t.Parallel()

	idp := newFakeIssuer(t, `{"keys":[]}`)

	err := oidc.ProbeValidators(t.Context(), []oidc.ValidatorConfig{{Issuer: idp.URL}}, nil)

	assert.ErrorContains(t, err, "jwks has no keys")
}

func TestProbeValidators_NamesOnlyTheIssuersThatFail(t *testing.T) {
	t.Parallel()

	up := newFakeIssuer(t, oneKey)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)

	err := oidc.ProbeValidators(t.Context(), []oidc.ValidatorConfig{{Issuer: up.URL}, {Issuer: down.URL}}, nil)

	require.ErrorContains(t, err, down.URL+": discovery")
	assert.NotContains(t, err.Error(), up.URL+":")
}

func TestProbeValidators_ProbesEachDistinctIssuerOnce(t *testing.T) {
	t.Parallel()

	idp := newFakeIssuer(t, oneKey)

	err := oidc.ProbeValidators(t.Context(), []oidc.ValidatorConfig{{Issuer: idp.URL}, {Issuer: idp.URL}}, nil)

	require.NoError(t, err)
	assert.Equal(t, int32(1), idp.discoveries.Load())
}

func TestProbeValidators_AHangingIssuerIsBoundedByTheContext(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); hang.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := oidc.ProbeValidators(ctx, []oidc.ValidatorConfig{{Issuer: hang.URL}}, nil)

	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}

package server

import (
	"context"
	"net/http"
	"time"

	"github.com/dioad/lifecycle"

	"github.com/dioad/auth/oidc"
)

const (
	// ValidatorCheckName is the name AddValidatorCheck registers the check under,
	// and so the key it has in a readiness report.
	ValidatorCheckName = "jwt-validators"

	// DefaultValidatorCheckTimeout caps the check and each of its requests. It is
	// below the 5s that Fly and lifecycle.DefaultCheckTimeout both use, so a hung
	// identity provider makes the check report degraded rather than the probe
	// itself time out.
	DefaultValidatorCheckTimeout = 2 * time.Second

	// DefaultValidatorCheckCacheTTL is how long a result is reused, so frequent
	// probes make at most one discovery and one JWKS request per issuer per
	// interval per instance.
	DefaultValidatorCheckCacheTTL = 30 * time.Second
)

// AddValidatorCheck adds a readiness check to r that every identity provider
// behind validators answers OIDC discovery and serves at least one signing key
// (see oidc.ProbeValidators). It adds nothing when no validator fetches keys:
// none configured, or all use a static HMAC secret.
//
// The check is degraded, not failing: an identity provider outage affects every
// instance alike, so failing readiness would take the whole service out of
// rotation without moving traffic anywhere that could validate tokens. A pass
// means each issuer was reachable within DefaultValidatorCheckCacheTTL; it does
// not prove the validators' own key caches are current.
//
// opts follow the defaults, so WithCheckTimeout or WithCacheTTL replaces them.
func AddValidatorCheck(r *lifecycle.Readiness, validators []oidc.ValidatorConfig, opts ...lifecycle.CheckOption) {
	if len(oidc.KeyFetchingIssuers(validators)) == 0 {
		return
	}
	client := &http.Client{Timeout: DefaultValidatorCheckTimeout}
	all := make([]lifecycle.CheckOption, 0, 3+len(opts))
	all = append(all,
		lifecycle.WithDegraded(),
		lifecycle.WithCacheTTL(DefaultValidatorCheckCacheTTL),
		lifecycle.WithCheckTimeout(DefaultValidatorCheckTimeout),
	)
	r.AddCheck(ValidatorCheckName, func(ctx context.Context) error {
		return oidc.ProbeValidators(ctx, validators, client)
	}, append(all, opts...)...)
}

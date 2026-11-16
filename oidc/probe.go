package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// ProbeValidators checks that every identity provider behind validators
// answers OIDC discovery and serves at least one signing key, using doer for
// the requests (nil means http.DefaultClient), and returns every failure
// joined. It returns nil when no validator fetches keys, so it is safe to call
// for any configuration; see KeyFetchingIssuers.
//
// It is for a readiness check. A pass means each issuer was reachable just
// now; it does not prove the validators' own key caches are current.
func ProbeValidators(ctx context.Context, validators []ValidatorConfig, doer HTTPDoer) error {
	if doer == nil {
		doer = http.DefaultClient
	}
	issuers := KeyFetchingIssuers(validators)
	errs := make([]error, len(issuers))
	var wg sync.WaitGroup
	for i, issuer := range issuers {
		wg.Go(func() { errs[i] = probeIssuer(ctx, doer, issuer) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// KeyFetchingIssuers returns the distinct issuers whose signing keys the
// validators discover, resolving each the way dioad/auth's validator does:
// the configured issuer, else the endpoint URL. HMAC validators use a static
// secret and fetch nothing.
func KeyFetchingIssuers(validators []ValidatorConfig) []string {
	var issuers []string
	seen := make(map[string]bool)
	for _, v := range validators {
		if v.withDeprecatedKeys().HMACSecret != "" {
			continue
		}
		issuer := v.Issuer
		if issuer == "" {
			issuer = v.URL
		}
		if issuer == "" || seen[issuer] {
			continue
		}
		seen[issuer] = true
		issuers = append(issuers, issuer)
	}
	return issuers
}

// probeIssuer fetches issuer's discovery document and then its JWKS, and
// requires at least one key.
func probeIssuer(ctx context.Context, doer HTTPDoer, issuer string) error {
	endpoint, err := NewEndpoint(issuer, WithHTTPDoer(doer))
	if err != nil {
		return fmt.Errorf("%s: %w", issuer, err)
	}
	discovered, err := endpoint.DiscoveredConfiguration(ctx)
	if err != nil {
		return fmt.Errorf("%s: discovery: %w", issuer, err)
	}
	if discovered.JWKSURI == "" {
		return fmt.Errorf("%s: discovery document has no jwks_uri", issuer)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discovered.JWKSURI, nil)
	if err != nil {
		return fmt.Errorf("%s: jwks: %w", issuer, err)
	}
	resp, err := doer.Do(req)
	if err != nil {
		return fmt.Errorf("%s: jwks: %w", issuer, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: jwks: status %d", issuer, resp.StatusCode)
	}
	var keySet struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&keySet); err != nil {
		return fmt.Errorf("%s: jwks: %w", issuer, err)
	}
	if len(keySet.Keys) == 0 {
		return fmt.Errorf("%s: jwks has no keys", issuer)
	}
	return nil
}

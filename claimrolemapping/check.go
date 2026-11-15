package claimrolemapping

import (
	"github.com/rs/zerolog"

	"github.com/dioad/config/configcheck"
)

// AcceptUnauthenticatedRiskKey is the second opt-in allow-unauthenticated
// needs, as it is named in configuration.
const AcceptUnauthenticatedRiskKey = "accept-unauthenticated-risk"

// Check reports to c how a service authenticates its API callers: either with
// jwt-validators (jwtValidators is how many are configured), or, for local
// development only, with allow-unauthenticated. Exactly one of the two must be
// configured. c is positioned at the configuration root, where the keys sit.
//
// allow-unauthenticated bypasses authentication and every RBAC check, so it
// also needs accept-unauthenticated-risk. That key without
// allow-unauthenticated has no effect and is reported. A claim-role mapping
// with debug set logs every claim map it evaluates, which carries personal and
// organisational data, so it needs enableDebug (the service's enable-debug)
// too: that keeps a copied rule from switching it on in production by itself.
func (c ExtractorConfig) Check(findings *configcheck.Collector, jwtValidators int, enableDebug bool) {
	unauthenticated := c.Unauthenticated()
	switch {
	case unauthenticated && !c.AcceptUnauthenticatedRisk:
		findings.Field("allow-unauthenticated").Errorf("bypasses authentication and RBAC; set %s: true to confirm this is not a production deployment", AcceptUnauthenticatedRiskKey)
	case !unauthenticated && c.AcceptUnauthenticatedRisk:
		findings.Field(AcceptUnauthenticatedRiskKey).Errorf("is set but has no effect without allow-unauthenticated, remove it")
	}
	if unauthenticated && jwtValidators > 0 {
		findings.Field("allow-unauthenticated").Errorf("and jwt-validators are mutually exclusive")
	}
	if !unauthenticated && jwtValidators == 0 {
		findings.Field("jwt-validators").Errorf("is required when allow-unauthenticated is false")
	}
	if enableDebug {
		return
	}
	for i, m := range c.ClaimRoleMappings {
		if m.Debug {
			findings.Field("claim-role-mappings").Index(i).Field("debug").Errorf("logs claim values for role %q; it requires enable-debug", m.Role)
		}
	}
}

// LogUnauthenticated logs, at error level, the startup messages for a service
// running with allow-unauthenticated, so every service words the risk
// identically and an error-level alert on startup logs catches it.
func LogUnauthenticated(logger zerolog.Logger) {
	logger.Error().Msg("JWT validation is disabled — all API requests are accepted without authentication")
	logger.Error().Msg("allow-unauthenticated is enabled: all authentication and RBAC checks are bypassed — do NOT use in production")
}

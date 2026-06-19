// Package claimrolemapping provides shared configuration types and constructor
// functions for building a PrincipalExtractor from claim-based role mapping
// rules. Services embed ExtractorConfig in their own config struct to share a
// consistent auth configuration surface.
package claimrolemapping

import (
	"github.com/dioad/auth"
	"github.com/rs/zerolog"
)

// Source name constants for use in ClaimRoleMappingConfig.Source.
const (
	SourceFlyio         = "flyio"
	SourceGithubActions = "githubactions"
	SourceAWS           = "aws"
	SourceOIDC          = "oidc"
	SourceJWT           = "jwt"
)

var knownSources = []string{SourceFlyio, SourceGithubActions, SourceAWS, SourceOIDC, SourceJWT}

// ClaimRoleMappingConfig maps a set of JWT claim predicates to an internal
// role, optionally restricted to a specific PrincipalSource. An empty Source
// matches any source.
type ClaimRoleMappingConfig struct {
	// Source restricts this mapping to a named PrincipalSource (e.g. "flyio",
	// "aws"). Empty means match any source.
	Source string `mapstructure:"source"`
	// Claims maps claim keys to required values. A value of "*" matches any
	// non-empty string.
	Claims map[string]string `mapstructure:"claims"`
	// Role is the internal role granted when all claim predicates match.
	Role string `mapstructure:"role"`
	// Debug enables per-request structured debug logging for this rule.
	// Do not enable in production — evaluated claim values appear in the log output.
	Debug bool `mapstructure:"debug"`
}

// ExtractorConfig is the common auth configuration for services that need
// JWT-based principal extraction with claim-to-role mapping. Embed this in a
// service config with the mapstructure ",squash" tag to preserve the flat YAML
// key structure.
type ExtractorConfig struct {
	AllowUnauthenticated bool                     `mapstructure:"allow-unauthenticated"`
	ClaimRoleMappings    []ClaimRoleMappingConfig `mapstructure:"claim-role-mappings"`
}

// BuildExtractorConfig constructs a per-source DefaultExtractorConfig from
// claim-role mapping rules. It emits Info-level startup logs for each
// configured source and a Warn when any rule has Debug enabled.
func BuildExtractorConfig(mappings []ClaimRoleMappingConfig, logger zerolog.Logger) auth.DefaultExtractorConfig {
	sourceMappings := make(map[string][]ClaimRoleMappingConfig, len(knownSources))
	for _, src := range knownSources {
		filtered := filterMappings(mappings, src)
		sourceMappings[src] = filtered
		if len(filtered) == 0 {
			continue
		}
		debugEnabled := false
		for _, m := range filtered {
			if m.Debug {
				debugEnabled = true
				break
			}
		}
		logger.Info().
			Str("source", src).
			Int("rule_count", len(filtered)).
			Bool("debug_logging", debugEnabled).
			Msg("claim-role-mapping: configured")
		if debugEnabled {
			logger.Warn().
				Str("source", src).
				Msg("claim-role-mapping: debug logging enabled — claim values will be logged; do not enable in production")
		}
	}

	return auth.DefaultExtractorConfig{
		FlyioMapper:         buildMapper(sourceMappings[SourceFlyio], SourceFlyio, logger),
		GithubActionsMapper: buildMapper(sourceMappings[SourceGithubActions], SourceGithubActions, logger),
		AWSMapper:           buildMapper(sourceMappings[SourceAWS], SourceAWS, logger),
		OIDCMapper:          buildMapper(sourceMappings[SourceOIDC], SourceOIDC, logger),
		JWTMapper:           buildMapper(sourceMappings[SourceJWT], SourceJWT, logger),
	}
}

// BuildPrincipalExtractor constructs a PrincipalExtractor from config. When
// AllowUnauthenticated is true it returns an allow-all extractor suitable for
// development. Otherwise it builds a proper extractor with per-source
// claim-to-role mapping.
func BuildPrincipalExtractor(config ExtractorConfig, logger zerolog.Logger) auth.PrincipalExtractor {
	if config.AllowUnauthenticated {
		return auth.NewAllowAllPrincipalExtractor()
	}
	return auth.NewDefaultPrincipalExtractorWithConfig(
		BuildExtractorConfig(config.ClaimRoleMappings, logger),
	)
}

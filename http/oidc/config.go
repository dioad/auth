package oidc

import authoidc "github.com/dioad/auth/oidc"

const (
	// SessionCookieName is the name of the cookie used to store the OIDC session.
	SessionCookieName = "dioad_session"
	// PreAuthRefererCookieName is the name of the cookie used to store the referer URL before authentication.
	PreAuthRefererCookieName = "auth_referer"
)

// ProviderConfig contains configuration for an OIDC provider.
//
// Deprecated: use `github.com/dioad/auth/oidc.ProviderConfig` directly.
type ProviderConfig = authoidc.ProviderConfig

// ProviderMap maps provider names to their configurations.
//
// Deprecated: use `github.com/dioad/auth/oidc.ProviderMap` directly.
type ProviderMap = authoidc.ProviderMap

// Config contains configuration for OIDC authentication.
//
// Deprecated: use `github.com/dioad/auth/oidc.Config` directly.
type Config = authoidc.Config

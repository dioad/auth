package authz

// RoleCapabilityConfig maps a role name to the capabilities it grants.
// Used in YAML/mapstructure-based configuration.
type RoleCapabilityConfig struct {
	// Role is the internal role name.
	Role string `mapstructure:"role"`

	// Capabilities is the list of capability strings granted to this role.
	// Each must use ':' as the separator, e.g. "tunnel:write", "feature:custom-domain".
	Capabilities []string `mapstructure:"capabilities"`
}

// AuthorizerConfig is the top-level config for constructing an [Authorizer]
// from a YAML/mapstructure config source.
type AuthorizerConfig struct {
	// RoleCapabilities is the list of role→capability assignments.
	RoleCapabilities []RoleCapabilityConfig `mapstructure:"role-capabilities"`

	// RoleAliases maps external token role names to internal role names.
	// Only roles listed here (as keys) are accepted; others are dropped.
	RoleAliases map[string]string `mapstructure:"role-aliases"`

	// AllowAll disables all policy checks; every capability is granted.
	// Must only be set in dev/test environments.
	AllowAll bool `mapstructure:"allow-all"`
}

// NewAuthorizer builds an [Authorizer] from c: an [AllowAllAuthorizer] when
// c.AllowAll is set — dev/test only, see AllowAll's doc comment — otherwise
// the default Casbin-backed RBAC authorizer built from c's role/capability
// metadata. This consolidates a wiring pattern ("allow-all flag picks between
// a bypass authorizer and the real RBAC backend") that callers have
// previously had to duplicate themselves.
func (c AuthorizerConfig) NewAuthorizer() (Authorizer, error) {
	metadata := c.ToMetadata()
	if c.AllowAll {
		return NewAllowAllAuthorizer(metadata), nil
	}
	return NewDefaultCasbinAuthorizer(metadata)
}

// ToMetadata converts the config into a [PolicyMetadata] value suitable for
// constructing a [RoleAuthorizer] or [CasbinAuthorizer].
func (c AuthorizerConfig) ToMetadata() PolicyMetadata {
	rc := make(map[Role][]Capability, len(c.RoleCapabilities))
	for _, rcc := range c.RoleCapabilities {
		caps := make([]Capability, 0, len(rcc.Capabilities))
		for _, s := range rcc.Capabilities {
			caps = append(caps, Capability(s))
		}
		rc[Role(rcc.Role)] = caps
	}

	aliases := make(map[string]Role, len(c.RoleAliases))
	for external, internal := range c.RoleAliases {
		aliases[external] = Role(internal)
	}

	return PolicyMetadata{
		RoleCapabilities: rc,
		RoleAliases:      aliases,
	}
}

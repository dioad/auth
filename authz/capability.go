// Package authz provides a unified authorization model for the dioad platform.
//
// # Capability model
//
// All permissions and feature entitlements are expressed as [Capability] values
// using the colon-separated convention inherited from Casbin:
//
//   - Feature entitlements: "feature:<name>" e.g. "feature:custom-domain"
//   - Resource:action permissions: "<resource>:<action>" e.g. "tunnel:write"
//
// Use [FeatureCapability] and [Permission] to construct typed capabilities rather
// than bare string literals.
//
// # Backends
//
// Multiple Authorizer implementations are provided:
//   - [AllowAllAuthorizer]: dev/test bypass — always grants
//   - [RoleAuthorizer]: in-memory role→capability map (lightweight, config-driven)
//   - [MapAuthorizer]: principal-ID→PrivilegeSet map (inline config, testing)
//   - [CasbinAuthorizer]: Casbin v2 policy engine (production)
//   - [MultiAuthorizer]: first-non-nil chain
//
// [CasbinAuthorizer] is the recommended production backend for both connect and
// connect-control.
package authz

import "strings"

// Capability is a named thing a principal is allowed to do or use.
// All capabilities use ':' as the separator (Casbin convention):
//
//	"feature:<name>"      — product entitlement (feature:custom-domain)
//	"<resource>:<action>" — resource:action permission (tunnel:write)
//
// Use [FeatureCapability] or [Permission] to construct values; avoid bare string
// literals in application code.
type Capability string

// FeatureCapability constructs a feature-namespace capability.
// For example, FeatureCapability("custom-domain") returns "feature:custom-domain".
func FeatureCapability(name string) Capability {
	return Capability("feature:" + name)
}

// Permission constructs a resource:action capability.
// For example, Permission("tunnel", "write") returns "tunnel:write".
func Permission(resource, action string) Capability {
	return Capability(resource + ":" + action)
}

// parts splits a Capability into (obj, act) for use with Casbin.
// For a well-formed capability like "tunnel:write" it returns ("tunnel", "write").
// For an unscoped value with no colon it returns ("", cap) so callers can detect
// the malformed case.
func (c Capability) parts() (obj, act string, ok bool) {
	obj, act, ok = strings.Cut(string(c), ":")
	return
}

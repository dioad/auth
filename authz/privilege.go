package authz

// Privilege represents the set of capabilities granted to a principal.
// Callers use [Has] to check whether a specific capability is present.
// The concrete implementation is [PrivilegeSet].
type Privilege interface {
	Has(Capability) bool
}

// PrivilegeSet is a capability set backed by a map. It implements [Privilege]
// and can be built incrementally via [Grant]. Use [NewPrivilegeSet] to create
// a set from a slice of known capabilities.
type PrivilegeSet struct {
	caps map[Capability]struct{}
}

// NewPrivilegeSet creates a PrivilegeSet containing the given capabilities.
func NewPrivilegeSet(caps ...Capability) *PrivilegeSet {
	ps := &PrivilegeSet{caps: make(map[Capability]struct{}, len(caps))}
	for _, c := range caps {
		ps.caps[c] = struct{}{}
	}
	return ps
}

// Has reports whether the set contains cap.
func (p *PrivilegeSet) Has(cap Capability) bool {
	if p == nil || p.caps == nil {
		return false
	}
	_, ok := p.caps[cap]
	return ok
}

// Grant adds cap to the set.
func (p *PrivilegeSet) Grant(cap Capability) {
	if p.caps == nil {
		p.caps = make(map[Capability]struct{})
	}
	p.caps[cap] = struct{}{}
}

// Capabilities returns a snapshot of all capabilities in the set.
func (p *PrivilegeSet) Capabilities() []Capability {
	if p == nil {
		return nil
	}
	caps := make([]Capability, 0, len(p.caps))
	for c := range p.caps {
		caps = append(caps, c)
	}
	return caps
}

// Union returns a new PrivilegeSet containing all capabilities from both sets
// (OR-merge). Neither input is modified.
func (p *PrivilegeSet) Union(other *PrivilegeSet) *PrivilegeSet {
	result := NewPrivilegeSet(p.Capabilities()...)
	if other != nil {
		for _, c := range other.Capabilities() {
			result.Grant(c)
		}
	}
	return result
}

// allowAllPrivilege is a Privilege that grants every capability.
type allowAllPrivilege struct{}

func (allowAllPrivilege) Has(Capability) bool { return true }

// wildcardAwarePrivilege wraps a PrivilegeSet and extends Has to honour the
// "resource:any" wildcard convention used by the Casbin model. A capability
// of the form "resource:action" is granted if the set contains the exact
// capability OR contains "resource:any".
//
// Use [NewWildcardPrivilege] to create one. This is the value returned by
// [CasbinAuthorizer.Privileges] and [RoleAuthorizer.Privileges] so that
// callers using the fetch-once/check-many pattern see consistent results
// with the Casbin enforce path used by [CasbinAuthorizer.Can].
type wildcardAwarePrivilege struct {
	set *PrivilegeSet
}

// NewWildcardPrivilege returns a Privilege backed by ps that additionally
// grants any "resource:action" capability when "resource:any" is present.
func NewWildcardPrivilege(ps *PrivilegeSet) Privilege {
	return wildcardAwarePrivilege{set: ps}
}

// Has reports whether the capability is granted, either exactly or via a
// "resource:any" wildcard for the same resource prefix.
func (w wildcardAwarePrivilege) Has(cap Capability) bool {
	if w.set == nil {
		return false
	}
	if w.set.Has(cap) {
		return true
	}
	// Check for wildcard: if the capability is "resource:action", also accept "resource:any".
	s := string(cap)
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			wildcard := Capability(s[:i+1] + "any")
			return w.set.Has(wildcard)
		}
	}
	return false
}

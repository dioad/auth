package auth

import "github.com/dioad/auth/mapper"

// ClaimRoleMapping maps a set of claim predicates to an internal role.
// All predicates must match (AND semantics). See mapper.ClaimRoleMapping for details.
type ClaimRoleMapping = mapper.ClaimRoleMapping

// ClaimRoleMapper maps a claims map to a list of roles.
// See mapper.Mapper for details.
type ClaimRoleMapper = mapper.Mapper

// NewClaimRoleMapper creates a ClaimRoleMapper from a list of ClaimRoleMapping rules.
// Returns nil if mappings is empty.
func NewClaimRoleMapper(mappings []ClaimRoleMapping) ClaimRoleMapper {
	return mapper.New(mappings)
}

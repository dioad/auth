package authz_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/dioad/auth"
	"github.com/dioad/auth/authz"
)

// ExampleCheck_roleAuthorizer decides whether a principal may use a capability. Roles come
// from the principal extractor, either from the token or from claim-role
// mapping rules. The authorizer maps roles to capabilities.
func ExampleCheck_roleAuthorizer() {
	authorizer := authz.NewRoleAuthorizer(authz.PolicyMetadata{
		RoleCapabilities: map[authz.Role][]authz.Capability{
			"publisher": {authz.Permission("tunnel", "write")},
			"reader":    {authz.Permission("tunnel", "read")},
		},
		// An external role name from the identity provider, mapped to an
		// internal role.
		RoleAliases: map[string]authz.Role{"connect-publisher": "publisher"},
	})

	ctx := context.Background()
	write := authz.Permission("tunnel", "write")

	publisher := &auth.PrincipalContext{ID: "alice", Roles: []string{"connect-publisher"}}
	reader := &auth.PrincipalContext{ID: "bob", Roles: []string{"reader"}}

	fmt.Println("publisher:", authz.Check(ctx, authorizer, publisher, write))

	// A denial is the bare sentinel, so it is safe to return to a client.
	err := authz.Check(ctx, authorizer, reader, write)
	fmt.Println("reader:", err, errors.Is(err, authz.ErrForbidden))

	// No principal at all is a different outcome: the caller is not signed in.
	err = authz.Check(ctx, authorizer, nil, write)
	fmt.Println("anonymous:", err, errors.Is(err, authz.ErrUnauthorized))

	// A service built without an authorizer denies everything.
	err = authz.Check(ctx, nil, publisher, write)
	fmt.Println("no authorizer:", err)

	// Output:
	// publisher: <nil>
	// reader: forbidden true
	// anonymous: unauthorized true
	// no authorizer: forbidden
}

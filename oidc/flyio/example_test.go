package flyio_test

import (
	"context"
	"fmt"

	"github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"

	"github.com/dioad/auth"
	"github.com/dioad/auth/oidc/flyio"
)

// ExamplePrincipalSource reads a Fly.io machine identity from a validated
// token and grants roles from its claims. The JWT middleware stores the
// validated token in the context; here that is done by hand.
func ExamplePrincipalSource() {
	source := &flyio.PrincipalSource{
		RoleMapper: auth.NewClaimRoleMapper([]auth.ClaimRoleMapping{
			{Claims: map[string]string{"org_name": "myorg", "app_name": "*"}, Role: "prod-agent"},
		}),
	}

	ctx := core.SetClaims(context.Background(), &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{Subject: "machine-123"},
		CustomClaims: &flyio.Claims{
			AppID:     "app-1",
			AppName:   "connect-server",
			OrgName:   "myorg",
			MachineID: "machine-123"},
	})

	principal, err := source.Extract(ctx)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("principal:", principal)
	fmt.Println("roles:", source.Roles(ctx))
	fmt.Println("service:", source.IsService(ctx))
	// Output:
	// principal: machine-123
	// roles: [prod-agent]
	// service: true
}

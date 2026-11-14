package githubactions_test

import (
	"context"
	"fmt"

	"github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"

	"github.com/dioad/auth"
	"github.com/dioad/auth/oidc/githubactions"
)

// ExamplePrincipalSource reads a GitHub Actions workflow identity from a
// validated token and grants the deployer role to one repository's main
// branch. The JWT middleware stores the validated token in the context; here
// that is done by hand.
func ExamplePrincipalSource() {
	source := &githubactions.PrincipalSource{
		RoleMapper: auth.NewClaimRoleMapper([]auth.ClaimRoleMapping{
			{
				Claims: map[string]string{"repository": "myorg/infrastructure", "ref": "refs/heads/main"},
				Role:   "deployer",
			},
		}),
	}

	token := func(ref string) context.Context {
		return core.SetClaims(context.Background(), &jwtvalidator.ValidatedClaims{
			RegisteredClaims: jwtvalidator.RegisteredClaims{Subject: "repo:myorg/infrastructure:ref:" + ref},
			CustomClaims: &githubactions.Claims{
				Repository:     "myorg/infrastructure",
				Ref:            ref,
				JobWorkflowRef: "myorg/infrastructure/.github/workflows/deploy.yaml@" + ref,
				RunID:          "42"},
		})
	}

	fmt.Println("main:", source.Roles(token("refs/heads/main")))
	fmt.Println("feature branch:", source.Roles(token("refs/heads/feature")))
	// Output:
	// main: [deployer]
	// feature branch: []
}

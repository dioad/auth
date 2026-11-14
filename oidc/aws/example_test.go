package aws_test

import (
	"context"
	"fmt"

	"github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"

	"github.com/dioad/auth"
	"github.com/dioad/auth/oidc/aws"
)

// ExamplePrincipalSource reads an AWS role identity from a validated token
// and grants roles by AWS account. AWS nests its claims under a namespace;
// the principal source flattens them to "aws_*" keys for the role mapping
// rules. The JWT middleware stores the validated token in the context; here
// that is done by hand.
func ExamplePrincipalSource() {
	source := &aws.PrincipalSource{
		RoleMapper: auth.NewClaimRoleMapper([]auth.ClaimRoleMapping{
			{Claims: map[string]string{"aws_account": "123456789012"}, Role: "aws-prod"},
		}),
	}

	var claims aws.Claims
	claims.HTTPSStsAmazonawsCom.AwsAccount = "123456789012"
	claims.HTTPSStsAmazonawsCom.PrincipalID = "AIDAJ12345EXAMPLE"

	ctx := core.SetClaims(context.Background(), &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{Subject: "arn:aws:iam::123456789012:role/ec2-instance"},
		CustomClaims:     &claims,
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
	// principal: arn:aws:iam::123456789012:role/ec2-instance
	// roles: [aws-prod]
	// service: true
}

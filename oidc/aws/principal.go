package aws

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dioad/auth/jwt"
	"github.com/dioad/auth/mapper"
)

// PrincipalSource extracts principal identity from AWS OIDC tokens.
type PrincipalSource struct {
	// RoleMapper maps raw AWS JWT claims to internal role strings.
	// When nil, Roles returns nil.
	RoleMapper mapper.Mapper
}

// Roles returns the internal roles derived from AWS claims via the configured
// RoleMapper. Returns nil when no mapper is set.
func (s *PrincipalSource) Roles(ctx context.Context) []string {
	if s.RoleMapper == nil {
		return nil
	}
	return s.RoleMapper.MapRoles(s.Claims(ctx))
}

func (s *PrincipalSource) Extract(ctx context.Context, _ *http.Request) (string, error) {
	claims := jwt.RegisteredClaimsFromContext(ctx)
	if claims != nil {
		return claims.Subject, nil
	}
	return "", fmt.Errorf("no principal found")
}

func (s *PrincipalSource) Name() string {
	return "aws"
}

// Claims returns the AWS OIDC token claims as a map. AWS STS custom claims are
// returned under their raw JWT claim names (nested under the STS namespace prefix).
func (s *PrincipalSource) Claims(ctx context.Context) map[string]any {
	result := make(map[string]any)

	claims := jwt.CustomClaimsFromContext[*CustomClaims](ctx)
	if claims != nil {
		sts := claims.HttpsStsAmazonawsCom
		result["aws_principal_id"] = sts.PrincipalId
		result["aws_org_id"] = sts.OrgId
		result["aws_source_region"] = sts.SourceRegion
		result["aws_account"] = sts.AwsAccount
		result["aws_ec2_source_instance_arn"] = sts.Ec2SourceInstanceArn
		result["aws_ec2_instance_source_vpc"] = sts.Ec2InstanceSourceVpc
		result["aws_ec2_instance_source_private_ipv4"] = sts.Ec2InstanceSourcePrivateIpv4
		result["aws_ec2_role_delivery"] = sts.Ec2RoleDelivery
	}

	return result
}

// IsService returns true for any valid AWS OIDC token, as these represent
// machine/role identities rather than human users.
func (s *PrincipalSource) IsService(ctx context.Context) bool {
	return jwt.CustomClaimsFromContext[*CustomClaims](ctx) != nil
}


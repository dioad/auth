package aws

import (
	"context"
	"maps"

	"github.com/dioad/auth/authctx"
	"github.com/dioad/auth/mapper"
	"github.com/dioad/auth/oidc/oidcutil"
)

// STSNamespace is the OIDC custom claim namespace for AWS STS.
const STSNamespace = "https://sts.amazonaws.com/"

// HasValidClaims reports whether claims contains the AWS STS namespace custom
// claims that identify an AWS OIDC token validated by a generic JWT middleware.
func HasValidClaims(claims map[string]any) bool {
	sts, ok := claims[STSNamespace].(map[string]any)
	if !ok || len(sts) == 0 {
		return false
	}
	return oidcutil.HasNonEmptyString(sts, "principal_id") || oidcutil.HasNonEmptyString(sts, "aws_account")
}

// NormalizeClaims flattens the nested AWS STS namespace claims from a
// raw OIDC token payload into the canonical aws_* prefixed form expected by
// ClaimRoleMapper rules. Returns nil when claims is empty. The input map is
// not modified; the returned map is a new copy.
func NormalizeClaims(claims map[string]any) map[string]any {
	if len(claims) == 0 {
		return nil
	}
	result := make(map[string]any, len(claims))
	maps.Copy(result, claims)

	sts, ok := claims[STSNamespace].(map[string]any)
	if !ok {
		return result
	}
	copyFromSTS(result, sts, "principal_id", "aws_principal_id")
	copyFromSTS(result, sts, "org_id", "aws_org_id")
	copyFromSTS(result, sts, "source_region", "aws_source_region")
	copyFromSTS(result, sts, "aws_account", "aws_account")
	copyFromSTS(result, sts, "ec2_source_instance_arn", "aws_ec2_source_instance_arn")
	copyFromSTS(result, sts, "ec2_instance_source_vpc", "aws_ec2_instance_source_vpc")
	copyFromSTS(result, sts, "ec2_instance_source_private_ipv4", "aws_ec2_instance_source_private_ipv4")
	copyFromSTS(result, sts, "ec2_role_delivery", "aws_ec2_role_delivery")
	return result
}

// ClaimsMap implements oidcutil.ClaimsMapper, flattening the typed AWS STS
// claims into canonical aws_* prefixed keys. AWS tokens don't seed a
// "username" key on the typed path, so subject is unused.
func (c *Claims) ClaimsMap(_ string) map[string]any {
	sts := c.HttpsStsAmazonawsCom
	return map[string]any{
		"aws_principal_id":                     sts.PrincipalId,
		"aws_org_id":                           sts.OrgId,
		"aws_source_region":                    sts.SourceRegion,
		"aws_account":                          sts.AwsAccount,
		"aws_ec2_source_instance_arn":          sts.Ec2SourceInstanceArn,
		"aws_ec2_instance_source_vpc":          sts.Ec2InstanceSourceVpc,
		"aws_ec2_instance_source_private_ipv4": sts.Ec2InstanceSourcePrivateIpv4,
		"aws_ec2_role_delivery":                sts.Ec2RoleDelivery,
	}
}

// PrincipalSource extracts principal identity from AWS OIDC tokens.
type PrincipalSource struct {
	// RoleMapper maps raw AWS JWT claims to internal role strings.
	// When nil, Roles returns nil.
	RoleMapper mapper.Mapper
}

// Roles returns the internal roles derived from AWS claims via the configured
// RoleMapper. Returns nil when no mapper is set.
func (s *PrincipalSource) Roles(ctx context.Context) []string {
	return oidcutil.GenericRoles(s.RoleMapper, s.Claims(ctx))
}

// Extract returns the principal subject from an AWS OIDC token. It first
// attempts the typed-claims path (JWT middleware configured with an AWS
// validator), then falls back to fingerprinting generic validated claims stored
// by a non-typed JWT middleware.
func (s *PrincipalSource) Extract(ctx context.Context) (string, error) {
	return oidcutil.GenericExtract[Claims](ctx, HasValidClaims)
}

func (s *PrincipalSource) Name() string {
	return "aws"
}

// Claims returns the AWS OIDC token claims as a map. AWS STS custom claims are
// flattened from the nested STS namespace into canonical aws_* prefixed keys
// so that ClaimRoleMapper rules can reference them uniformly across both the
// typed and generic validation paths.
func (s *PrincipalSource) Claims(ctx context.Context) map[string]any {
	return oidcutil.GenericClaims[Claims](ctx, HasValidClaims, genericClaims)
}

// IsService returns true for any valid AWS OIDC token, as these represent
// machine/role identities rather than human users.
func (s *PrincipalSource) IsService(ctx context.Context) bool {
	return oidcutil.GenericIsService[Claims](ctx, HasValidClaims)
}

// genericClaims builds the fallback-path Claims() result: normalize nested
// STS claims into flat aws_* keys, alongside the raw custom claims.
func genericClaims(ctx context.Context, custom map[string]any) map[string]any {
	result := make(map[string]any)
	maps.Copy(result, NormalizeClaims(custom))
	if _, exists := result["username"]; !exists {
		if principal, ok := authctx.AuthenticatedPrincipalFromContext(ctx); ok && principal != "" {
			result["username"] = principal
		}
	}
	return result
}

func copyFromSTS(result, sts map[string]any, srcKey, dstKey string) {
	if _, exists := result[dstKey]; exists {
		return
	}
	v, ok := sts[srcKey].(string)
	if !ok || v == "" {
		return
	}
	result[dstKey] = v
}

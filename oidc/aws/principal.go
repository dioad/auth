package aws

import (
	"context"
	"maps"
	"net/http"

	authcontext "github.com/dioad/auth/http/context"
	"github.com/dioad/auth/jwt"
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

// Extract returns the principal subject from an AWS OIDC token. It first
// attempts the typed-claims path (JWT middleware configured with an AWS
// validator), then falls back to fingerprinting generic validated claims stored
// by a non-typed JWT middleware.
func (s *PrincipalSource) Extract(ctx context.Context, _ *http.Request) (string, error) {
	// Typed path: JWT middleware configured with an AWS-specific validator.
	if claims := jwt.CustomClaimsFromContext[*Claims](ctx); claims != nil {
		registered := jwt.RegisteredClaimsFromContext(ctx)
		if registered == nil {
			return "", nil
		}
		return registered.Subject, nil
	}
	// Generic path: JWT middleware using a generic validator. Fingerprint the
	// custom claims map to confirm this is an AWS token before extracting.
	custom, ok := authcontext.AuthenticatedCustomClaimsFromContext(ctx)
	if !ok || !HasValidClaims(custom) {
		return "", nil
	}
	if principal, ok := authcontext.AuthenticatedPrincipalFromContext(ctx); ok && principal != "" {
		return principal, nil
	}
	if sub, ok := custom["sub"].(string); ok && sub != "" {
		return sub, nil
	}
	return "", nil
}

func (s *PrincipalSource) Name() string {
	return "aws"
}

// Claims returns the AWS OIDC token claims as a map. AWS STS custom claims are
// flattened from the nested STS namespace into canonical aws_* prefixed keys
// so that ClaimRoleMapper rules can reference them uniformly across both the
// typed and generic validation paths.
func (s *PrincipalSource) Claims(ctx context.Context) map[string]any {
	result := make(map[string]any)

	// Typed path.
	if claims := jwt.CustomClaimsFromContext[*Claims](ctx); claims != nil {
		sts := claims.HttpsStsAmazonawsCom
		result["aws_principal_id"] = sts.PrincipalId
		result["aws_org_id"] = sts.OrgId
		result["aws_source_region"] = sts.SourceRegion
		result["aws_account"] = sts.AwsAccount
		result["aws_ec2_source_instance_arn"] = sts.Ec2SourceInstanceArn
		result["aws_ec2_instance_source_vpc"] = sts.Ec2InstanceSourceVpc
		result["aws_ec2_instance_source_private_ipv4"] = sts.Ec2InstanceSourcePrivateIpv4
		result["aws_ec2_role_delivery"] = sts.Ec2RoleDelivery
		return result
	}

	// Generic path: normalize nested STS claims into flat aws_* keys.
	custom, ok := authcontext.AuthenticatedCustomClaimsFromContext(ctx)
	if !ok || !HasValidClaims(custom) {
		return result
	}
	maps.Copy(result, NormalizeClaims(custom))
	if _, exists := result["username"]; !exists {
		if principal, ok := authcontext.AuthenticatedPrincipalFromContext(ctx); ok && principal != "" {
			result["username"] = principal
		}
	}
	return result
}

// IsService returns true for any valid AWS OIDC token, as these represent
// machine/role identities rather than human users.
func (s *PrincipalSource) IsService(ctx context.Context) bool {
	if jwt.CustomClaimsFromContext[*Claims](ctx) != nil {
		return true
	}
	custom, _ := authcontext.AuthenticatedCustomClaimsFromContext(ctx)
	return HasValidClaims(custom)
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

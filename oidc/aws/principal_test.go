package aws

import (
	"context"
	"testing"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeCustomClaims is a helper to create AWS CustomClaims with the nested STS struct.
func makeCustomClaims(principalId, orgId, awsAccount, region string) CustomClaims {
	return CustomClaims{
		HttpsStsAmazonawsCom: struct {
			Ec2InstanceSourceVpc         string    `json:"ec2_instance_source_vpc"`
			Ec2RoleDelivery              string    `json:"ec2_role_delivery"`
			OrgId                        string    `json:"org_id"`
			AwsAccount                   string    `json:"aws_account"`
			OuPath                       []string  `json:"ou_path"`
			OriginalSessionExp           time.Time `json:"original_session_exp"`
			SourceRegion                 string    `json:"source_region"`
			Ec2SourceInstanceArn         string    `json:"ec2_source_instance_arn"`
			PrincipalId                  string    `json:"principal_id"`
			Ec2InstanceSourcePrivateIpv4 string    `json:"ec2_instance_source_private_ipv4"`
		}{
			PrincipalId:                  principalId,
			OrgId:                        orgId,
			AwsAccount:                   awsAccount,
			SourceRegion:                 region,
			Ec2SourceInstanceArn:         "arn:aws:ec2:us-east-1:123456789012:instance/i-123456",
			Ec2InstanceSourceVpc:         "vpc-12345",
			Ec2InstanceSourcePrivateIpv4: "10.0.0.1",
			Ec2RoleDelivery:              "ec2-role",
		},
	}
}

// TestExtract_WithAWSClaims verifies that Extract returns the subject from AWS claims.
func TestExtract_WithAWSClaims(t *testing.T) {
	claims := &Claims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "arn:aws:iam::123456789012:role/connect-server",
		},
		CustomClaims: makeCustomClaims("principal-789", "org-456", "123456789012", "us-east-1"),
	}

	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "arn:aws:iam::123456789012:role/connect-server",
		},
		CustomClaims: claims,
	}
	ctx := core.SetClaims(context.Background(), vc)

	s := &PrincipalSource{}
	principal, err := s.Extract(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, "arn:aws:iam::123456789012:role/connect-server", principal)
}

// TestExtract_WithoutAWSClaims verifies that Extract returns empty string and nil error
// when AWS claims are absent. This is the "not applicable" case for the fallback chain.
func TestExtract_WithoutAWSClaims(t *testing.T) {
	// Store a different claim type (e.g., generic OIDC token)
	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "some-user",
		},
		CustomClaims: nil, // No AWS claims
	}
	ctx := core.SetClaims(context.Background(), vc)

	s := &PrincipalSource{}
	principal, err := s.Extract(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, "", principal)
}

// TestExtract_EmptyContext verifies that Extract returns empty string and nil error
// when no claims are in context at all.
func TestExtract_EmptyContext(t *testing.T) {
	s := &PrincipalSource{}
	principal, err := s.Extract(context.Background(), nil)

	require.NoError(t, err)
	assert.Equal(t, "", principal)
}

// TestName verifies that Name returns the provider identifier.
func TestName(t *testing.T) {
	s := &PrincipalSource{}
	assert.Equal(t, "aws", s.Name())
}

// TestIsService verifies that IsService returns true only when AWS claims are present.
func TestIsService(t *testing.T) {
	tests := []struct {
		name     string
		claims   jwtvalidator.CustomClaims
		wantTrue bool
	}{
		{
			name: "with aws claims",
			claims: &Claims{
				CustomClaims: makeCustomClaims("principal-123", "org-123", "123456789012", "us-west-2"),
			},
			wantTrue: true,
		},
		{
			name:     "without aws claims",
			claims:   nil,
			wantTrue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vc := &jwtvalidator.ValidatedClaims{
				CustomClaims: tt.claims,
			}
			ctx := core.SetClaims(context.Background(), vc)

			s := &PrincipalSource{}
			assert.Equal(t, tt.wantTrue, s.IsService(ctx))
		})
	}
}

// TestClaims verifies that Claims returns a map with provider-specific keys.
func TestClaims(t *testing.T) {
	claims := &Claims{
		CustomClaims: makeCustomClaims("principal-789", "org-456", "123456789012", "us-east-1"),
	}

	vc := &jwtvalidator.ValidatedClaims{
		CustomClaims: claims,
	}
	ctx := core.SetClaims(context.Background(), vc)

	s := &PrincipalSource{}
	claimsMap := s.Claims(ctx)

	// Verify provider-specific keys
	assert.Equal(t, "principal-789", claimsMap["aws_principal_id"])
	assert.Equal(t, "org-456", claimsMap["aws_org_id"])
	assert.Equal(t, "us-east-1", claimsMap["aws_source_region"])
	assert.Equal(t, "123456789012", claimsMap["aws_account"])
	assert.Equal(t, "arn:aws:ec2:us-east-1:123456789012:instance/i-123456", claimsMap["aws_ec2_source_instance_arn"])
	assert.Equal(t, "vpc-12345", claimsMap["aws_ec2_instance_source_vpc"])
	assert.Equal(t, "10.0.0.1", claimsMap["aws_ec2_instance_source_private_ipv4"])
	assert.Equal(t, "ec2-role", claimsMap["aws_ec2_role_delivery"])
}

// TestClaims_EmptyContext verifies that Claims returns an empty map when no claims are present.
func TestClaims_EmptyContext(t *testing.T) {
	s := &PrincipalSource{}
	claimsMap := s.Claims(context.Background())

	assert.NotNil(t, claimsMap)
	assert.Empty(t, claimsMap)
}

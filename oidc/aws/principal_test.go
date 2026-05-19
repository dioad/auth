package aws

import (
	"context"
	"testing"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authcontext "github.com/dioad/auth/http/context"
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

// TestHasValidClaims verifies the AWS fingerprint predicate.
func TestHasValidClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{
			name: "STS namespace with principal_id",
			claims: map[string]any{
				"https://sts.amazonaws.com/": map[string]any{
					"principal_id": "arn:aws:sts::123456789012:assumed-role/my-role/session",
				},
			},
			want: true,
		},
		{
			name: "STS namespace with aws_account",
			claims: map[string]any{
				"https://sts.amazonaws.com/": map[string]any{
					"aws_account": "123456789012",
				},
			},
			want: true,
		},
		{
			name: "STS namespace both present",
			claims: map[string]any{
				"https://sts.amazonaws.com/": map[string]any{
					"principal_id": "arn:aws:sts::123456789012:assumed-role/my-role/session",
					"aws_account":  "123456789012",
				},
			},
			want: true,
		},
		{
			name: "no STS namespace",
			claims: map[string]any{
				"aws_account": "123456789012",
			},
			want: false,
		},
		{
			name: "empty STS namespace",
			claims: map[string]any{
				"https://sts.amazonaws.com/": map[string]any{},
			},
			want: false,
		},
		{
			name:   "empty claims",
			claims: map[string]any{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, HasValidClaims(tt.claims))
		})
	}
}

// TestNormalizeClaims verifies that nested STS claims are flattened into
// the canonical aws_* prefixed form.
func TestNormalizeClaims(t *testing.T) {
	input := map[string]any{
		"sub": "arn:aws:sts::123456789012:assumed-role/my-role/session",
		"https://sts.amazonaws.com/": map[string]any{
			"principal_id":  "arn:aws:sts::123456789012:assumed-role/my-role/session",
			"org_id":        "o-12345",
			"source_region": "eu-west-2",
			"aws_account":   "123456789012",
		},
	}

	result := NormalizeClaims(input)

	assert.Equal(t, "arn:aws:sts::123456789012:assumed-role/my-role/session", result["aws_principal_id"])
	assert.Equal(t, "o-12345", result["aws_org_id"])
	assert.Equal(t, "eu-west-2", result["aws_source_region"])
	assert.Equal(t, "123456789012", result["aws_account"])
	// Original claims are preserved
	assert.Equal(t, "arn:aws:sts::123456789012:assumed-role/my-role/session", result["sub"])
}

// TestNormalizeClaims_NilInput verifies that nil input returns nil.
func TestNormalizeClaims_NilInput(t *testing.T) {
	assert.Nil(t, NormalizeClaims(nil))
}

// TestExtract_WithGenericClaims verifies that Extract returns the principal from
// authcontext generic claims when they fingerprint as an AWS token.
func TestExtract_WithGenericClaims(t *testing.T) {
	claims := map[string]any{
		"https://sts.amazonaws.com/": map[string]any{
			"principal_id": "arn:aws:sts::123456789012:assumed-role/my-role/session",
			"aws_account":  "123456789012",
		},
	}
	ctx := authcontext.ContextWithAuthenticatedPrincipal(context.Background(), "aws:sts:web-identity")
	ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, claims)

	s := &PrincipalSource{}
	principal, err := s.Extract(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, "aws:sts:web-identity", principal)
}

// TestExtract_WithGenericClaims_NoMatch verifies that Extract returns empty
// string when generic claims do not fingerprint as AWS.
func TestExtract_WithGenericClaims_NoMatch(t *testing.T) {
	claims := map[string]any{
		"aws_account": "123456789012", // flat, not nested under STS namespace
	}
	ctx := authcontext.ContextWithAuthenticatedPrincipal(context.Background(), "some-principal")
	ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, claims)

	s := &PrincipalSource{}
	principal, err := s.Extract(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, "", principal)
}

// TestIsService_WithGenericClaims verifies IsService returns true for AWS
// generic claims and false for non-matching generic claims.
func TestIsService_WithGenericClaims(t *testing.T) {
	t.Run("matching generic claims", func(t *testing.T) {
		ctx := authcontext.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{
			"https://sts.amazonaws.com/": map[string]any{
				"principal_id": "arn:aws:sts::123456789012:assumed-role/my-role/session",
			},
		})
		s := &PrincipalSource{}
		assert.True(t, s.IsService(ctx))
	})

	t.Run("non-matching generic claims", func(t *testing.T) {
		ctx := authcontext.ContextWithAuthenticatedCustomClaims(context.Background(), map[string]any{
			"aws_account": "123456789012",
		})
		s := &PrincipalSource{}
		assert.False(t, s.IsService(ctx))
	})
}

// TestClaims_WithGenericClaims verifies that Claims returns normalized aws_*
// keys from generic context claims when they fingerprint as an AWS token.
func TestClaims_WithGenericClaims(t *testing.T) {
	claims := map[string]any{
		"https://sts.amazonaws.com/": map[string]any{
			"principal_id":  "arn:aws:sts::123456789012:assumed-role/my-role/session",
			"org_id":        "o-12345",
			"source_region": "eu-west-2",
			"aws_account":   "123456789012",
		},
	}
	ctx := authcontext.ContextWithAuthenticatedPrincipal(context.Background(), "aws:sts:web-identity")
	ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, claims)

	s := &PrincipalSource{}
	result := s.Claims(ctx)

	assert.Equal(t, "arn:aws:sts::123456789012:assumed-role/my-role/session", result["aws_principal_id"])
	assert.Equal(t, "o-12345", result["aws_org_id"])
	assert.Equal(t, "eu-west-2", result["aws_source_region"])
	assert.Equal(t, "123456789012", result["aws_account"])
}

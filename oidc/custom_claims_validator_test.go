package oidc_test

import (
	"context"
	"testing"
	"time"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/oidc"
	"github.com/dioad/auth/oidc/aws"
	"github.com/dioad/auth/oidc/flyio"
	"github.com/dioad/auth/oidc/githubactions"
)

// These tests verify that validators created with provider-specific Type
// configurations produce typed custom claims that the corresponding
// PrincipalSource implementations can extract.
//
// Kent Beck's testing desiderata guides:
//   - Isolated: each test is self-contained with its own HMAC key, no shared state
//   - Deterministic: fixed HMAC signing, no network calls; uses time.Now() for iat/exp
//   - Fast: in-process validation only, no JWKS fetches
//   - Readable: each test states the scenario clearly in its name and assertions
//   - Behavioral: tests assert on observable output (claim types), not internal wiring
//   - Structure-insensitive: tests don't depend on how the validator is internally built
//   - Composable: each provider test is independent, can run in any order
//   - Specific: failures pinpoint exactly which claim type was wrong

const testHMACSecret = "test-custom-claims-secret"

func flyioToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"sub":             "dioad-dev:dioad-dev-edgerouter:cold-shape-2007",
		"iss":             "https://oidc.fly.io/dioad-dev",
		"aud":             []string{"test"},
		"iat":             now.Unix(),
		"exp":             now.Add(1 * time.Hour).Unix(),
		"app_id":          "5148555",
		"app_name":        "dioad-dev-edgerouter",
		"org_id":          "837952",
		"org_name":        "dioad-dev",
		"machine_id":      "d8dd4edce23568",
		"machine_name":    "cold-shape-2007",
		"machine_version": "01KRV9N8WDDTZQ701CSDRMQH07",
		"image":           "registry.fly.io/dioad-dev-edgerouter:deployment-01KRV9M2HFP46H8EHB5G6B33FJ",
		"image_digest":    "sha256:130638176c7724751a50ef648bd288bddd276c56e87b981b320aa172e7afcf43",
		"region":          "lhr",
	})
	s, err := token.SignedString([]byte(testHMACSecret))
	require.NoError(t, err)
	return s
}

func awsToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"sub": "arn:aws:iam::481665101164:role/dev-dioad-public-dns",
		"iss": "https://sts.amazonaws.com",
		"aud": []string{"test"},
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
		"https://sts.amazonaws.com/": map[string]any{
			"principal_id":                     "arn:aws:iam::481665101164:role/dev-dioad-public-dns",
			"org_id":                           "o-abc123",
			"aws_account":                      "481665101164",
			"source_region":                    "eu-west-2",
			"ec2_source_instance_arn":          "",
			"ec2_instance_source_vpc":          "",
			"ec2_instance_source_private_ipv4": "",
			"ec2_role_delivery":                "",
		},
	})
	s, err := token.SignedString([]byte(testHMACSecret))
	require.NoError(t, err)
	return s
}

func githubActionsToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"sub":                 "repo:dioad/connect-control:ref:refs/heads/main",
		"iss":                 "https://token.actions.githubusercontent.com",
		"aud":                 []string{"test"},
		"iat":                 now.Unix(),
		"exp":                 now.Add(1 * time.Hour).Unix(),
		"actor":               "patrickdowney",
		"actor_id":            "12345",
		"repository":          "dioad/connect-control",
		"repository_id":       "67890",
		"repository_owner":    "dioad",
		"repository_owner_id": "11111",
		"ref":                 "refs/heads/main",
		"ref_type":            "branch",
		"event_name":          "push",
		"workflow":            "CI",
		"run_id":              "999",
		"run_number":          "42",
		"run_attempt":         "1",
		"sha":                 "abc123def456",
		"environment":         "production",
		"runner_environment":  "github-hosted",
		"job_workflow_ref":    "dioad/connect-control/.github/workflows/ci.yml@refs/heads/main",
		"workflow_ref":        "dioad/connect-control/.github/workflows/ci.yml@refs/heads/main",
		"workflow_sha":        "abc123def456",
		"head_ref":            "",
		"base_ref":            "",
	})
	s, err := token.SignedString([]byte(testHMACSecret))
	require.NoError(t, err)
	return s
}

// TestFlyioValidatorProducesTypedClaims verifies that a validator configured
// with Type "flyio" deserializes JWT custom claims into *flyio.Claims, enabling
// the flyio.PrincipalSource to extract principal identity.
func TestFlyioValidatorProducesTypedClaims(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret: testHMACSecret,
		Audiences:  []string{"test"},
	}
	cfg.Type = "flyio"

	v, err := oidc.NewValidatorFromConfig(cfg)
	require.NoError(t, err)

	out, err := v.ValidateToken(context.Background(), flyioToken(t))
	require.NoError(t, err)

	vc, ok := out.(*jwtvalidator.ValidatedClaims)
	require.True(t, ok, "expected *ValidatedClaims, got %T", out)

	flyioClaims, ok := vc.CustomClaims.(*flyio.Claims)
	require.True(t, ok, "expected *flyio.Claims, got %T", vc.CustomClaims)

	require.Equal(t, "dioad-dev-edgerouter", flyioClaims.AppName)
	require.Equal(t, "dioad-dev", flyioClaims.OrgName)
	require.Equal(t, "lhr", flyioClaims.Region)
	require.Equal(t, "5148555", flyioClaims.AppId)
	require.Equal(t, "d8dd4edce23568", flyioClaims.MachineId)
}

// TestAWSValidatorProducesTypedClaims verifies that a validator configured
// with Type "aws" deserializes JWT custom claims into *aws.Claims, including
// the nested STS namespace claims.
func TestAWSValidatorProducesTypedClaims(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret: testHMACSecret,
		Audiences:  []string{"test"},
	}
	cfg.Type = "aws"

	v, err := oidc.NewValidatorFromConfig(cfg)
	require.NoError(t, err)

	out, err := v.ValidateToken(context.Background(), awsToken(t))
	require.NoError(t, err)

	vc, ok := out.(*jwtvalidator.ValidatedClaims)
	require.True(t, ok, "expected *ValidatedClaims, got %T", out)

	awsClaims, ok := vc.CustomClaims.(*aws.Claims)
	require.True(t, ok, "expected *aws.Claims, got %T", vc.CustomClaims)

	require.Equal(t, "arn:aws:iam::481665101164:role/dev-dioad-public-dns",
		awsClaims.HttpsStsAmazonawsCom.PrincipalId)
	require.Equal(t, "481665101164", awsClaims.HttpsStsAmazonawsCom.AwsAccount)
	require.Equal(t, "eu-west-2", awsClaims.HttpsStsAmazonawsCom.SourceRegion)
	require.Equal(t, "o-abc123", awsClaims.HttpsStsAmazonawsCom.OrgId)
}

// TestGitHubActionsValidatorProducesTypedClaims verifies that a validator
// configured with Type "githubactions" deserializes JWT custom claims into
// *githubactions.Claims.
func TestGitHubActionsValidatorProducesTypedClaims(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret: testHMACSecret,
		Audiences:  []string{"test"},
	}
	cfg.Type = "githubactions"

	v, err := oidc.NewValidatorFromConfig(cfg)
	require.NoError(t, err)

	out, err := v.ValidateToken(context.Background(), githubActionsToken(t))
	require.NoError(t, err)

	vc, ok := out.(*jwtvalidator.ValidatedClaims)
	require.True(t, ok, "expected *ValidatedClaims, got %T", out)

	ghClaims, ok := vc.CustomClaims.(*githubactions.Claims)
	require.True(t, ok, "expected *githubactions.Claims, got %T", vc.CustomClaims)

	require.Equal(t, "patrickdowney", ghClaims.Actor)
	require.Equal(t, "dioad/connect-control", ghClaims.Repository)
	require.Equal(t, "dioad", ghClaims.RepositoryOwner)
	require.Equal(t, "refs/heads/main", ghClaims.Ref)
	require.Equal(t, "push", ghClaims.EventName)
	require.Equal(t, "CI", ghClaims.Workflow)
}

// TestDefaultTypeProducesGenericClaims verifies that a validator without
// a provider-specific Type still produces generic claims (the existing behavior).
// This ensures backwards compatibility.
func TestDefaultTypeProducesGenericClaims(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret: testHMACSecret,
		Audiences:  []string{"test"},
		// Type intentionally not set — should use default (IntrospectionResponse)
	}

	v, err := oidc.NewValidatorFromConfig(cfg)
	require.NoError(t, err)

	out, err := v.ValidateToken(context.Background(), flyioToken(t))
	require.NoError(t, err)

	vc, ok := out.(*jwtvalidator.ValidatedClaims)
	require.True(t, ok, "expected *ValidatedClaims, got %T", out)

	// Default behavior: custom claims should NOT be *flyio.Claims
	_, isFlyio := vc.CustomClaims.(*flyio.Claims)
	require.False(t, isFlyio, "default validator should not produce *flyio.Claims")
}

// TestCustomClaimsValidatorOption verifies that the WithValidatorCustomClaimsFactory
// option can override the claims factory regardless of config Type.
func TestCustomClaimsValidatorOption(t *testing.T) {
	cfg := &oidc.ValidatorConfig{
		HMACSecret: testHMACSecret,
		Audiences:  []string{"test"},
		// Type not set — factory override should take effect
	}

	v, err := oidc.NewValidatorFromConfigWithOptions(cfg,
		oidc.WithValidatorCustomClaimsFactory(func() jwtvalidator.CustomClaims {
			return &flyio.Claims{}
		}),
	)
	require.NoError(t, err)

	out, err := v.ValidateToken(context.Background(), flyioToken(t))
	require.NoError(t, err)

	vc, ok := out.(*jwtvalidator.ValidatedClaims)
	require.True(t, ok)

	flyioClaims, ok := vc.CustomClaims.(*flyio.Claims)
	require.True(t, ok, "custom claims factory should produce *flyio.Claims, got %T", vc.CustomClaims)
	require.Equal(t, "dioad-dev-edgerouter", flyioClaims.AppName)
}

package auth_test

import (
	"context"
	"net/http/httptest"
	"testing"

	jwtcore "github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth"
	authcontext "github.com/dioad/auth/http/context"
	"github.com/dioad/auth/oidc/aws"
	"github.com/dioad/auth/oidc/flyio"
	"github.com/dioad/auth/oidc/githubactions"
)

// These tests verify the full end-to-end flow: typed claims in context →
// provider PrincipalSource extracts principal → role mapper assigns roles.
//
// This is the critical integration that was broken: the flyio/aws/githubactions
// PrincipalSources only fire when their typed Claims struct is in context.
// With the WithCustomClaims fix, the validator now produces typed claims,
// so these sources are invoked and role mappings work correctly.
//
// Kent Beck's desiderata:
//   - Behavioral: tests assert on the observable outcome (roles assigned via source)
//   - Isolated: each test sets up its own context and extractor
//   - Deterministic: no network, no randomness
//   - Fast: pure in-process context manipulation
//   - Readable: each test clearly names the provider and expected outcome
//   - Composable: tests are independent, covering different providers

// simulateTypedClaimsContext simulates what the JWT middleware handler does
// when a validator with WithCustomClaims is used: it stores the
// ValidatedClaims (containing typed custom claims) in context via core.SetClaims,
// and also stores the subject and custom claims map in auth/http/context.
func simulateTypedClaimsContext(ctx context.Context, vc *jwtvalidator.ValidatedClaims, customClaimsMap map[string]any) context.Context {
	ctx = jwtcore.SetClaims(ctx, vc)
	if vc.RegisteredClaims.Subject != "" {
		ctx = authcontext.ContextWithAuthenticatedPrincipal(ctx, vc.RegisteredClaims.Subject)
		ctx = authcontext.ContextWithAuthenticatedRegisteredClaims(ctx, vc.RegisteredClaims)
	}
	if len(customClaimsMap) > 0 {
		ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, customClaimsMap)
	}
	return ctx
}

// TestFlyioPrincipalSource_WithTypedClaims_AssignsRoles verifies that when
// *flyio.Claims are in context (as produced by a validator with Type "flyio"),
// the flyio PrincipalSource extracts the principal and the role mapper assigns
// the correct role — fixing the original 403 bug.
func TestFlyioPrincipalSource_WithTypedClaims_AssignsRoles(t *testing.T) {
	extractor := auth.NewDefaultPrincipalExtractorWithConfig(auth.DefaultExtractorConfig{
		FlyioMapper: auth.NewClaimRoleMapper([]auth.ClaimRoleMapping{
			{
				Claims: map[string]string{
					"org_name": "dioad-dev",
					"app_name": "dioad-dev-edgerouter",
				},
				Role: "registry.router-reader",
			},
		}),
	})

	flyioClaims := &flyio.Claims{
		CustomClaims: flyio.CustomClaims{
			AppId:   "5148555",
			AppName: "dioad-dev-edgerouter",
			OrgId:   "837952",
			OrgName: "dioad-dev",
			Region:  "lhr",
		},
	}
	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "dioad-dev:dioad-dev-edgerouter:cold-shape-2007",
		},
		CustomClaims: flyioClaims,
	}

	ctx := simulateTypedClaimsContext(context.Background(), vc, map[string]any{
		"app_name": "dioad-dev-edgerouter",
		"org_name": "dioad-dev",
	})
	req := httptest.NewRequest("GET", "/v1/endpoints", nil).WithContext(ctx)

	principal, err := extractor.ExtractPrincipal(req.Context(), req)
	require.NoError(t, err)
	require.Equal(t, "flyio", principal.Source, "should be extracted by flyio source")
	require.Contains(t, principal.Roles, "registry.router-reader")
	require.True(t, principal.IsService, "flyio tokens represent service identities")
}

// TestAWSPrincipalSource_WithTypedClaims_AssignsRoles verifies that when
// *aws.Claims are in context, the aws PrincipalSource extracts the principal
// and maps the nested STS claims to roles.
func TestAWSPrincipalSource_WithTypedClaims_AssignsRoles(t *testing.T) {
	extractor := auth.NewDefaultPrincipalExtractorWithConfig(auth.DefaultExtractorConfig{
		AWSMapper: auth.NewClaimRoleMapper([]auth.ClaimRoleMapping{
			{
				Claims: map[string]string{
					"aws_principal_id": "arn:aws:iam::481665101164:role/dev-dioad-public-dns",
				},
				Role: "registry.dns-reader",
			},
		}),
	})

	awsClaims := &aws.Claims{}
	awsClaims.HttpsStsAmazonawsCom.PrincipalId = "arn:aws:iam::481665101164:role/dev-dioad-public-dns"
	awsClaims.HttpsStsAmazonawsCom.AwsAccount = "481665101164"
	awsClaims.HttpsStsAmazonawsCom.SourceRegion = "eu-west-2"

	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "arn:aws:iam::481665101164:role/dev-dioad-public-dns",
		},
		CustomClaims: awsClaims,
	}

	ctx := simulateTypedClaimsContext(context.Background(), vc, nil)
	req := httptest.NewRequest("GET", "/v1/endpoints", nil).WithContext(ctx)

	principal, err := extractor.ExtractPrincipal(req.Context(), req)
	require.NoError(t, err)
	require.Equal(t, "aws", principal.Source, "should be extracted by aws source")
	require.Contains(t, principal.Roles, "registry.dns-reader")
	require.True(t, principal.IsService, "aws tokens represent service identities")
}

// TestGitHubActionsPrincipalSource_WithTypedClaims_AssignsRoles verifies that
// when *githubactions.Claims are in context, the githubactions PrincipalSource
// extracts the principal and maps workflow claims to roles.
func TestGitHubActionsPrincipalSource_WithTypedClaims_AssignsRoles(t *testing.T) {
	extractor := auth.NewDefaultPrincipalExtractorWithConfig(auth.DefaultExtractorConfig{
		GithubActionsMapper: auth.NewClaimRoleMapper([]auth.ClaimRoleMapping{
			{
				Claims: map[string]string{
					"repository_owner": "dioad",
					"repository":       "dioad/connect-control",
				},
				Role: "registry.deployer",
			},
		}),
	})

	ghClaims := &githubactions.Claims{
		CustomClaims: githubactions.CustomClaims{
			Actor:           "patrickdowney",
			Repository:      "dioad/connect-control",
			RepositoryOwner: "dioad",
			Ref:             "refs/heads/main",
			EventName:       "push",
			Workflow:        "CI",
		},
	}

	vc := &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{
			Subject: "repo:dioad/connect-control:ref:refs/heads/main",
		},
		CustomClaims: ghClaims,
	}

	ctx := simulateTypedClaimsContext(context.Background(), vc, nil)
	req := httptest.NewRequest("GET", "/v1/endpoints", nil).WithContext(ctx)

	principal, err := extractor.ExtractPrincipal(req.Context(), req)
	require.NoError(t, err)
	require.Equal(t, "githubactions", principal.Source, "should be extracted by githubactions source")
	require.Contains(t, principal.Roles, "registry.deployer")
	require.True(t, principal.IsService, "githubactions tokens represent service identities")
}

// TestFlyioSource_WithoutTypedClaims_FallsThrough confirms the original bug:
// without typed claims, the flyio source returns "" and the token falls through
// to the jwt source, where source:flyio mappings don't apply.
func TestFlyioSource_WithoutTypedClaims_FallsThrough(t *testing.T) {
	extractor := auth.NewDefaultPrincipalExtractorWithConfig(auth.DefaultExtractorConfig{
		FlyioMapper: auth.NewClaimRoleMapper([]auth.ClaimRoleMapping{
			{
				Claims: map[string]string{
					"org_name": "dioad-dev",
					"app_name": "dioad-dev-edgerouter",
				},
				Role: "registry.router-reader",
			},
		}),
	})

	// Simulate the OLD behavior: generic claims in auth/http/context, no typed claims
	ctx := context.Background()
	ctx = authcontext.ContextWithAuthenticatedPrincipal(ctx, "dioad-dev:dioad-dev-edgerouter:cold-shape-2007")
	ctx = authcontext.ContextWithAuthenticatedCustomClaims(ctx, map[string]any{
		"app_name": "dioad-dev-edgerouter",
		"org_name": "dioad-dev",
	})
	req := httptest.NewRequest("GET", "/v1/endpoints", nil).WithContext(ctx)

	principal, err := extractor.ExtractPrincipal(req.Context(), req)
	require.NoError(t, err)
	require.Equal(t, "jwt", principal.Source, "without typed claims, should fall through to jwt source")
	require.NotContains(t, principal.Roles, "registry.router-reader",
		"flyio mapper should NOT be invoked by the jwt source")
}

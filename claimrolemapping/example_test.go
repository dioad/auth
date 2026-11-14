package claimrolemapping_test

import (
	"context"
	"fmt"

	"github.com/auth0/go-jwt-middleware/v3/core"
	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/rs/zerolog"

	"github.com/dioad/auth/claimrolemapping"
	"github.com/dioad/auth/oidc/flyio"
)

// ExampleBuildExtractorConfig maps an AWS account to a role. AWS tokens expose
// the account as the claim "aws_account".
func ExampleBuildExtractorConfig() {
	extractor := claimrolemapping.BuildExtractorConfig([]claimrolemapping.ClaimRoleMappingConfig{
		{
			Source: claimrolemapping.SourceAWS,
			Claims: map[string]string{"aws_account": "123456789012"},
			Role:   "aws-prod",
		},
	}, zerolog.Nop())

	roles := extractor.AWSMapper.MapRoles(map[string]any{
		"aws_account":      "123456789012",
		"aws_principal_id": "AIDAJ12345EXAMPLE",
	})
	fmt.Println(roles)
	// Output: [aws-prod]
}

// ExampleBuildExtractorConfig_flyioEnvironment grants a role to every app in
// a Fly.io environment. The wildcard "*" accepts any non-empty value, so the
// rule also requires the claim to be present.
func ExampleBuildExtractorConfig_flyioEnvironment() {
	extractor := claimrolemapping.BuildExtractorConfig([]claimrolemapping.ClaimRoleMappingConfig{
		{
			Source: claimrolemapping.SourceFlyio,
			Claims: map[string]string{"environment": "production", "app_name": "*"},
			Role:   "prod-agent",
		},
	}, zerolog.Nop())

	roles := extractor.FlyioMapper.MapRoles(map[string]any{
		"environment": "production",
		"app_name":    "connect-server",
	})
	fmt.Println(roles)
	// Output: [prod-agent]
}

// ExampleBuildExtractorConfig_githubActionsWorkflow grants a deploy role to
// one repository's main branch. A rule with several claims needs all of them
// to match.
func ExampleBuildExtractorConfig_githubActionsWorkflow() {
	extractor := claimrolemapping.BuildExtractorConfig([]claimrolemapping.ClaimRoleMappingConfig{
		{
			Source: claimrolemapping.SourceGithubActions,
			Claims: map[string]string{"repository": "myorg/infrastructure", "ref": "refs/heads/main"},
			Role:   "deployer",
		},
	}, zerolog.Nop())

	main := map[string]any{"repository": "myorg/infrastructure", "ref": "refs/heads/main"}
	branch := map[string]any{"repository": "myorg/infrastructure", "ref": "refs/heads/feature"}

	fmt.Println("main:", extractor.GithubActionsMapper.MapRoles(main))
	fmt.Println("feature branch:", extractor.GithubActionsMapper.MapRoles(branch))
	// Output:
	// main: [deployer]
	// feature branch: []
}

// ExampleBuildExtractorConfig_multipleRoles shows that every rule is checked
// on its own: a token receives the role of each rule it satisfies.
func ExampleBuildExtractorConfig_multipleRoles() {
	extractor := claimrolemapping.BuildExtractorConfig([]claimrolemapping.ClaimRoleMappingConfig{
		{Claims: map[string]string{"environment": "production"}, Role: "prod"},
		{Claims: map[string]string{"team": "*"}, Role: "team-member"},
	}, zerolog.Nop())

	roles := extractor.OIDCMapper.MapRoles(map[string]any{
		"environment": "production",
		"team":        "backend",
	})
	fmt.Println(roles)
	// Output: [prod team-member]
}

// ExampleBuildExtractorConfig_wildcardMatching shows what "*" matches: any
// non-empty value, but not an absent claim.
func ExampleBuildExtractorConfig_wildcardMatching() {
	extractor := claimrolemapping.BuildExtractorConfig([]claimrolemapping.ClaimRoleMappingConfig{
		{Claims: map[string]string{"username": "deploy-sa", "team": "*"}, Role: "service-account"},
	}, zerolog.Nop())

	fmt.Println("exact user, any team:", extractor.OIDCMapper.MapRoles(map[string]any{"username": "deploy-sa", "team": "platform"}))
	fmt.Println("other user:", extractor.OIDCMapper.MapRoles(map[string]any{"username": "deploy", "team": "platform"}))
	fmt.Println("no team:", extractor.OIDCMapper.MapRoles(map[string]any{"username": "deploy-sa"}))
	// Output:
	// exact user, any team: [service-account]
	// other user: []
	// no team: []
}

// ExampleBuildExtractorConfig_noMatch shows that a token no rule matches gets
// no roles. It is not an error: the authorizer decides what no roles may do.
func ExampleBuildExtractorConfig_noMatch() {
	extractor := claimrolemapping.BuildExtractorConfig([]claimrolemapping.ClaimRoleMappingConfig{
		{Claims: map[string]string{"environment": "production"}, Role: "prod"},
	}, zerolog.Nop())

	roles := extractor.OIDCMapper.MapRoles(map[string]any{"environment": "development"})
	fmt.Println(roles)
	// Output: []
}

// ExampleBuildExtractorConfig_arrayClaim shows matching against an array
// claim such as a Keycloak "groups" claim: the rule matches when any element
// equals the required value.
func ExampleBuildExtractorConfig_arrayClaim() {
	extractor := claimrolemapping.BuildExtractorConfig([]claimrolemapping.ClaimRoleMappingConfig{
		{Claims: map[string]string{"groups": "platform-admins"}, Role: "admin"},
	}, zerolog.Nop())

	member := map[string]any{"groups": []any{"everyone", "platform-admins"}}
	outsider := map[string]any{"groups": []any{"everyone"}}

	fmt.Println("member:", extractor.OIDCMapper.MapRoles(member))
	fmt.Println("outsider:", extractor.OIDCMapper.MapRoles(outsider))
	// Output:
	// member: [admin]
	// outsider: []
}

// ExampleBuildExtractorConfig_sourceFiltering shows that a rule with a Source
// applies to that source only, so one claim name can mean different things
// for different providers. A rule with no Source applies to every source.
func ExampleBuildExtractorConfig_sourceFiltering() {
	extractor := claimrolemapping.BuildExtractorConfig([]claimrolemapping.ClaimRoleMappingConfig{
		{Source: claimrolemapping.SourceFlyio, Claims: map[string]string{"environment": "production"}, Role: "prod"},
		{Source: claimrolemapping.SourceAWS, Claims: map[string]string{"environment": "production"}, Role: "aws-prod"},
	}, zerolog.Nop())

	claims := map[string]any{"environment": "production"}

	fmt.Println("Fly.io:", extractor.FlyioMapper.MapRoles(claims))
	fmt.Println("AWS:", extractor.AWSMapper.MapRoles(claims))
	fmt.Println("GitHub Actions:", extractor.GithubActionsMapper == nil)
	// Output:
	// Fly.io: [prod]
	// AWS: [aws-prod]
	// GitHub Actions: true
}

// ExampleBuildPrincipalExtractor is the production setup: claim-role mapping
// rules from configuration become a PrincipalExtractor. Here a Fly.io token
// that the JWT middleware validated has been stored in the context.
func ExampleBuildPrincipalExtractor() {
	extractor := claimrolemapping.BuildPrincipalExtractor(claimrolemapping.ExtractorConfig{
		ClaimRoleMappings: []claimrolemapping.ClaimRoleMappingConfig{
			{Source: claimrolemapping.SourceFlyio, Claims: map[string]string{"app_name": "connect-server"}, Role: "prod-agent"},
			{Source: claimrolemapping.SourceAWS, Claims: map[string]string{"aws_account": "123456789012"}, Role: "aws-prod"},
		},
	}, zerolog.Nop())

	ctx := core.SetClaims(context.Background(), &jwtvalidator.ValidatedClaims{
		RegisteredClaims: jwtvalidator.RegisteredClaims{Subject: "machine-123"},
		CustomClaims: &flyio.Claims{
			AppID:     "app-1",
			AppName:   "connect-server",
			MachineID: "machine-123"},
	})

	principal, err := extractor.ExtractPrincipal(ctx)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("principal:", principal.ID)
	fmt.Println("source:", principal.Source)
	fmt.Println("roles:", principal.Roles)
	fmt.Println("service:", principal.IsService)
	// Output:
	// principal: machine-123
	// source: flyio
	// roles: [prod-agent]
	// service: true
}

// ExampleBuildPrincipalExtractor_allowUnauthenticated shows the development
// switch. It makes every request the anonymous principal, so it must never be
// set in production.
func ExampleBuildPrincipalExtractor_allowUnauthenticated() {
	allow := true
	extractor := claimrolemapping.BuildPrincipalExtractor(claimrolemapping.ExtractorConfig{
		AllowUnauthenticated: &allow,
	}, zerolog.Nop())

	principal, _ := extractor.ExtractPrincipal(context.Background())
	fmt.Println(principal.ID, principal.IsAllowAll())
	// Output: unauthenticated true
}

// ExampleValidateRoleMappings catches a rule that names a role the
// authorizer does not know, which would silently grant nothing.
func ExampleValidateRoleMappings() {
	warnings := claimrolemapping.ValidateRoleMappings([]claimrolemapping.ClaimRoleMappingConfig{
		{Claims: map[string]string{"team": "*"}, Role: "team-member"},
		{Claims: map[string]string{"team": "ops"}, Role: "operator"},
	}, []string{"team-member", "admin"})

	for _, w := range warnings {
		fmt.Println(w)
	}
	// Output:
	// claim-role-mapping: unknown role operator — principals with this role may be denied; check your configuration
}

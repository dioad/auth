// Package aws provides functionality to retrieve OIDC tokens from AWS STS GetWebIdentityToken API.
// It defines a token source that implements oauth2.TokenSource, allowing for easy integration with
// OAuth2 libraries and frameworks. The package also includes support for custom claims and configurable
// options for audience, signing algorithm, and AWS configuration.
package aws

import (
	"context"
	"fmt"
	"time"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/oauth2"
)

type stsFactory func(cfg aws.Config) stsClient

type imdsClient interface {
	GetRegion(ctx context.Context, params *imds.GetRegionInput, optFns ...func(*imds.Options)) (*imds.GetRegionOutput, error)
}

// Opt defines a functional option for configuring the token source. It allows for setting various parameters such as
// audience, signing algorithm, and AWS configuration when creating a new token source.
type Opt func(*tokenSource)

// CustomClaims represents the custom claims included in the JWT token returned by AWS STS GetWebIdentityToken API.
// These claims provide additional information about the AWS environment and the context of the token issuance.
type CustomClaims struct {
	HttpsStsAmazonawsCom struct {
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
	} `json:"https://sts.amazonaws.com/"`
}

// Claims represents the JWT claims returned by the AWS OIDC provider, including both standard registered claims and
// custom AWS-specific claims.
type Claims struct {
	jwtvalidator.RegisteredClaims
	CustomClaims
}

// Validate implements the jwtvalidator.Claims interface. It can be used to perform custom validation on the claims if needed.
func (c *Claims) Validate(_ context.Context) error { return nil }

// tokenSource implements oauth2.TokenSource to retrieve OIDC tokens from AWS STS
type tokenSource struct {
	audience         string
	signingAlgorithm string
	region           string
	awsConfig        *aws.Config
	stsClient        stsClient
	stsFactory       stsFactory
	imdsClient       imdsClient
}

type stsClient interface {
	GetWebIdentityToken(ctx context.Context, params *sts.GetWebIdentityTokenInput, optFns ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error)
}

// Token retrieves a new OIDC token from the AWS STS GetWebIdentityToken API
func (c *tokenSource) Token() (*oauth2.Token, error) {
	if c.stsClient == nil {
		var awsConfig aws.Config
		var err error

		if c.awsConfig != nil {
			awsConfig = *c.awsConfig
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			region := c.region
			if region == "" {
				var client imdsClient = c.imdsClient
				if client == nil {
					client = imds.New(imds.Options{})
				}
				if out, err := client.GetRegion(ctx, &imds.GetRegionInput{}); err == nil {
					region = out.Region
				}
			}

			var optFns []func(*config.LoadOptions) error
			if region != "" {
				optFns = append(optFns, config.WithRegion(region))
			}

			awsConfig, err = config.LoadDefaultConfig(ctx, optFns...)
			if err != nil {
				return nil, fmt.Errorf("failed to load AWS config: %w", err)
			}
		}
		if c.stsFactory != nil {
			c.stsClient = c.stsFactory(awsConfig)
		} else {
			c.stsClient = sts.NewFromConfig(awsConfig)
		}
	}

	params := &sts.GetWebIdentityTokenInput{
		Audience:         []string{c.audience},
		SigningAlgorithm: aws.String(c.signingAlgorithm),
	}

	stsCtx, stsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stsCancel()
	response, err := c.stsClient.GetWebIdentityToken(stsCtx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get web identity token: %w", err)
	}

	if response == nil {
		return nil, fmt.Errorf("received nil response from GetWebIdentityToken")
	}

	if response.WebIdentityToken == nil || response.Expiration == nil {
		return nil, fmt.Errorf("response missing required fields: WebIdentityToken or Expiration")
	}

	token := &oauth2.Token{
		AccessToken: *response.WebIdentityToken,
		TokenType:   "bearer",
		Expiry:      *response.Expiration,
	}

	return token, nil
}

// WithAudience sets the audience for the OIDC token
func WithAudience(aud string) Opt {
	return func(ts *tokenSource) {
		if aud != "" {
			ts.audience = aud
		}
	}
}

// WithSigningAlgorithm sets the signing algorithm for the OIDC token
func WithSigningAlgorithm(alg string) Opt {
	return func(ts *tokenSource) {
		if alg != "" {
			ts.signingAlgorithm = alg
		}
	}
}

// WithAWSConfig sets the AWS configuration for the token source
func WithAWSConfig(cfg aws.Config) Opt {
	return func(ts *tokenSource) {
		ts.awsConfig = &cfg
	}
}

// WithRegion sets the AWS region for the token source. If not set, it will be automatically
// discovered from the EC2 metadata service or the default AWS configuration.
func WithRegion(region string) Opt {
	return func(ts *tokenSource) {
		ts.region = region
	}
}

// WithSTSClient sets a custom STS client for the token source.
func WithSTSClient(client stsClient) Opt {
	return func(ts *tokenSource) {
		if client != nil {
			ts.stsClient = client
		}
	}
}

// WithIMDSClient sets a custom IMDS client for the token source.
func WithIMDSClient(client imdsClient) Opt {
	return func(ts *tokenSource) {
		if client != nil {
			ts.imdsClient = client
		}
	}
}

// NewTokenSource creates a new token source configured with the provided options.
// It returns an oauth2.TokenSource that can be used to retrieve OIDC tokens from AWS.
func NewTokenSource(opts ...Opt) oauth2.TokenSource {
	source := &tokenSource{
		signingAlgorithm: "RS256", // Default signing algorithm for AWS STS
	}
	for _, opt := range opts {
		opt(source)
	}

	return source
}

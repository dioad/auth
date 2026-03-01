package aws

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSTSClient struct {
	input  *sts.GetWebIdentityTokenInput
	output *sts.GetWebIdentityTokenOutput
	err    error
}

func (f *fakeSTSClient) GetWebIdentityToken(_ context.Context, params *sts.GetWebIdentityTokenInput, _ ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error) {
	f.input = params
	return f.output, f.err
}

func TestNewTokenSource(t *testing.T) {
	ts := NewTokenSource(
		WithAudience("my-audience"),
		WithSigningAlgorithm("RS256"),
	).(*tokenSource)
	assert.NotNil(t, ts)
	assert.Equal(t, "my-audience", ts.audience)
	assert.Equal(t, "RS256", ts.signingAlgorithm)
}

func TestWithAWSConfig(t *testing.T) {
	cfg := aws.Config{Region: "us-east-1"}
	ts := NewTokenSource(WithAWSConfig(cfg)).(*tokenSource)
	assert.NotNil(t, ts.awsConfig)
	assert.Equal(t, "us-east-1", ts.awsConfig.Region)
}

func TestTokenUsesInjectedSTSClient(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	tokenValue := "token-value"
	client := &fakeSTSClient{
		output: &sts.GetWebIdentityTokenOutput{
			WebIdentityToken: &tokenValue,
			Expiration:       &expiry,
		},
	}

	stsTokenSource := NewTokenSource(
		WithAudience("aud"),
		WithSigningAlgorithm("RS256"),
		WithSTSClient(client),
	).(*tokenSource)

	result, err := stsTokenSource.Token()
	require.NoError(t, err)
	assert.Equal(t, tokenValue, result.AccessToken)
	assert.Equal(t, expiry, result.Expiry)
	require.NotNil(t, client.input)
	assert.Equal(t, []string{"aud"}, client.input.Audience)
	assert.Equal(t, aws.String("RS256"), client.input.SigningAlgorithm)
}

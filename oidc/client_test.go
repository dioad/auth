package oidc_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/oidc"
)

func TestClient_ClientID(t *testing.T) {
	endpoint, err := oidc.NewEndpoint("https://issuer.example")
	require.NoError(t, err)

	client := oidc.NewClient(endpoint, oidc.WithClientIDAndSecret("test-client-id", "test-client-secret"))

	require.Equal(t, "test-client-id", client.ClientID())
}

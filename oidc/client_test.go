package oidc_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/oidc"
)

func TestClient_ClientID(t *testing.T) {
	endpoint, err := oidc.NewEndpoint("https://issuer.example")
	require.NoError(t, err)

	client := oidc.NewClient(endpoint, oidc.WithClientIDAndSecret("test-client-id", "test-client-secret"))

	require.Equal(t, "test-client-id", client.ClientID())
}

func TestWithScope(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		want  string
	}{
		{name: "sets scope when non-empty", scope: "profile", want: "profile"},
		{name: "sets space-delimited multiple scopes", scope: "profile email", want: "profile email"},
		{name: "leaves scope unset when empty", scope: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := url.Values{}
			oidc.WithScope(tc.scope)(v)
			assert.Equal(t, tc.want, v.Get("scope"))
		})
	}
}

func TestWithAudience(t *testing.T) {
	tests := []struct {
		name     string
		audience string
		want     string
	}{
		{name: "sets audience when non-empty", audience: "urn:example:audience", want: "urn:example:audience"},
		{name: "leaves audience unset when empty", audience: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := url.Values{}
			oidc.WithAudience(tc.audience)(v)
			assert.Equal(t, tc.want, v.Get("audience"))
		})
	}
}

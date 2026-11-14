package oidc_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dioad/config/configcheck"
	"github.com/dioad/util"

	"github.com/dioad/auth/oidc"
)

func TestClientConfig_Check(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  oidc.ClientConfig
		want []configcheck.Finding
	}{
		{"no secret", oidc.ClientConfig{}, nil},
		{"secret only", oidc.ClientConfig{ClientSecret: *util.NewMaskedString("s3cret")}, nil},
		{"file only", oidc.ClientConfig{ClientSecretFile: "/run/secrets/oidc"}, nil},
		{"both", oidc.ClientConfig{ClientSecret: *util.NewMaskedString("s3cret"), ClientSecretFile: "/run/secrets/oidc"},
			[]configcheck.Finding{{Path: "identity.client-secret-file", Message: oidc.ErrClientSecretConflict.Error()}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			findings := configcheck.NewCollector()

			tt.cfg.Check(findings.Field("identity"))

			assert.Equal(t, tt.want, findings.Findings())
		})
	}
}

func TestClientConfig_Check_DoesNotReadTheFile(t *testing.T) {
	t.Parallel()
	findings := configcheck.NewCollector()

	(&oidc.ClientConfig{ClientSecretFile: "/no/such/file"}).Check(findings)

	assert.Empty(t, findings.Findings(), "a mounted secret may not exist where the config is validated")
}

func ExampleClientConfig_Check() {
	cfg := oidc.ClientConfig{
		ClientSecret:     *util.NewMaskedString("s3cret"),
		ClientSecretFile: "/run/secrets/oidc",
	}

	findings := configcheck.NewCollector()
	cfg.Check(findings.Field("identity"))

	for _, f := range findings.Findings() {
		fmt.Println(f)
	}
	// Output: identity.client-secret-file: client-secret and client-secret-file are mutually exclusive
}

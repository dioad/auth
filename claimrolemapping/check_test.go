package claimrolemapping_test

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/dioad/config/configcheck"

	"github.com/dioad/auth/claimrolemapping"
)

func TestExtractorConfig_Check(t *testing.T) {
	t.Parallel()

	yes, no := true, false
	debugRule := []claimrolemapping.ClaimRoleMappingConfig{{Role: "admin", Debug: true}}

	tests := []struct {
		name       string
		cfg        claimrolemapping.ExtractorConfig
		validators int
		debug      bool
		want       []configcheck.Finding
	}{
		{name: "validators only", validators: 1},
		{name: "unauthenticated with acknowledgement", cfg: claimrolemapping.ExtractorConfig{AllowUnauthenticated: &yes, AcceptUnauthenticatedRisk: true}},
		{
			name: "unauthenticated without acknowledgement",
			cfg:  claimrolemapping.ExtractorConfig{AllowUnauthenticated: &yes},
			want: []configcheck.Finding{{Path: "allow-unauthenticated", Message: "bypasses authentication and RBAC; set accept-unauthenticated-risk: true to confirm this is not a production deployment"}},
		},
		{
			name:       "unauthenticated with validators",
			cfg:        claimrolemapping.ExtractorConfig{AllowUnauthenticated: &yes, AcceptUnauthenticatedRisk: true},
			validators: 1,
			want:       []configcheck.Finding{{Path: "allow-unauthenticated", Message: "and jwt-validators are mutually exclusive"}},
		},
		{
			name: "neither validators nor unauthenticated",
			cfg:  claimrolemapping.ExtractorConfig{AllowUnauthenticated: &no},
			want: []configcheck.Finding{{Path: "jwt-validators", Message: "is required when allow-unauthenticated is false"}},
		},
		{
			name:       "acknowledgement without unauthenticated",
			cfg:        claimrolemapping.ExtractorConfig{AcceptUnauthenticatedRisk: true},
			validators: 1,
			want:       []configcheck.Finding{{Path: "accept-unauthenticated-risk", Message: "is set but has no effect without allow-unauthenticated, remove it"}},
		},
		{
			name:       "debug rule without enable-debug",
			cfg:        claimrolemapping.ExtractorConfig{ClaimRoleMappings: debugRule},
			validators: 1,
			want:       []configcheck.Finding{{Path: "claim-role-mappings[0].debug", Message: `logs claim values for role "admin"; it requires enable-debug`}},
		},
		{name: "debug rule with enable-debug", cfg: claimrolemapping.ExtractorConfig{ClaimRoleMappings: debugRule}, validators: 1, debug: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := configcheck.NewCollector()
			tc.cfg.Check(c, tc.validators, tc.debug)

			assert.Equal(t, tc.want, c.Findings())
		})
	}
}

func TestLogUnauthenticated_LogsTheRiskAtErrorLevel(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	claimrolemapping.LogUnauthenticated(zerolog.New(&buf))

	assert.Equal(t, 2, bytes.Count(buf.Bytes(), []byte(`"level":"error"`)))
	assert.Contains(t, buf.String(), "allow-unauthenticated is enabled")
}

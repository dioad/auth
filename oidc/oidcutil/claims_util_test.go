package oidcutil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dioad/auth/oidc/oidcutil"
)

func TestHasNonEmptyString(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		key  string
		want bool
	}{
		{"key missing", map[string]any{}, "k", false},
		{"empty string", map[string]any{"k": ""}, "k", false},
		{"non-empty string", map[string]any{"k": "v"}, "k", true},
		{"wrong type", map[string]any{"k": 42}, "k", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, oidcutil.HasNonEmptyString(tt.m, tt.key))
		})
	}
}

func TestHasAnyNonEmptyString(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		keys []string
		want bool
	}{
		{"no keys match", map[string]any{"a": ""}, []string{"a", "b"}, false},
		{"first key matches", map[string]any{"a": "x"}, []string{"a", "b"}, true},
		{"second key matches", map[string]any{"b": "x"}, []string{"a", "b"}, true},
		{"no keys given", map[string]any{"a": "x"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, oidcutil.HasAnyNonEmptyString(tt.m, tt.keys...))
		})
	}
}

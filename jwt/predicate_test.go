package jwt

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestClaimKeyPredicate(t *testing.T) {
	predicate := &ClaimKey{Key: "role", Value: "admin"}
	claims := jwt.MapClaims{"role": "admin"}
	assert.True(t, predicate.Validate(claims))

	claims = jwt.MapClaims{"role": []any{"user", "admin"}}
	assert.True(t, predicate.Validate(claims))

	claims = jwt.MapClaims{"role": "user"}
	assert.False(t, predicate.Validate(claims))
}

func TestParseClaimPredicates(t *testing.T) {
	input := map[string]any{
		"and": []any{
			map[string]any{"env": "prod"},
			map[string]any{
				"or": []any{
					map[string]any{"role": "admin"},
					map[string]any{"role": "editor"},
				},
			},
		},
	}

	predicate := ParseClaimPredicates(input)
	claims := jwt.MapClaims{"env": "prod", "role": "admin"}
	assert.True(t, predicate.Validate(claims))

	claims = jwt.MapClaims{"env": "prod", "role": "viewer"}
	assert.False(t, predicate.Validate(claims))
}

func TestParseSingleKeyValueClaimPredicate(t *testing.T) {
	input := map[string]any{
		"key": "value",
	}

	cp := ParseClaimPredicates(input)

	claims := map[string]any{
		"key": "value",
	}

	if !cp.Validate(claims) {
		t.Error("expected true")
	}
}

func TestParseSingleKeyListClaimPredicate(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		claims   jwt.MapClaims
		expected bool
	}{
		{
			name: "string value",
			input: map[string]any{
				"key": "value",
			},
			claims: jwt.MapClaims{
				"key": []any{"value"},
			},
			expected: true,
		},
		{
			name: "string value second",
			input: map[string]any{
				"key": "value",
			},
			claims: jwt.MapClaims{
				"key": []any{"value2", "value"},
			},
			expected: true,
		},
		{
			name: "string list contains value",
			input: map[string]any{
				"key": "value3",
			},
			claims: jwt.MapClaims{
				"key": []any{"value1", "value2"},
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := ParseClaimPredicates(tc.input)

			if cp.Validate(tc.claims) != tc.expected {
				t.Errorf("expected %v", tc.expected)
			}
		})
	}
}

func TestParseClaimPredicateMap(t *testing.T) {
	input := map[string]any{
		"key":  "value",
		"key2": "value2",
	}

	cp := ParseClaimPredicates(input)

	claims := jwt.MapClaims{
		"key":  "value",
		"key2": "value2",
	}

	if !cp.Validate(claims) {
		t.Error("expected true")
	}
}

func TestParseAndClaimPredicate(t *testing.T) {
	input := map[string]any{
		"and": []map[string]any{
			{
				"key": "value",
			},
			{
				"key2": "value2",
			},
		},
	}

	cp := ParseClaimPredicates(input)

	claims := jwt.MapClaims{
		"key":  "value",
		"key2": "value2",
	}

	if !cp.Validate(claims) {
		t.Error("expected true")
	}
}

func TestParseOrClaimPredicate(t *testing.T) {
	input := map[string]any{
		"or": []map[string]any{
			{
				"key": "value",
			},
			{
				"key2": "value2",
			},
		},
	}

	cp := ParseClaimPredicates(input)

	claims := jwt.MapClaims{
		"key":  "value",
		"key3": "value3",
	}

	if !cp.Validate(claims) {
		t.Error("expected true")
	}
}

func TestParseOrWithEmbeddedAnyClaimPredicate(t *testing.T) {
	input := map[string]any{
		"or": []map[string]any{
			{
				"key": "value",
			},
			{
				"and": []map[string]any{
					{
						"key2": "value2",
					},
					{
						"key3": "value3",
					},
				},
			},
		},
	}

	cp := ParseClaimPredicates(input)

	claims := jwt.MapClaims{
		"key":  "value",
		"key3": "value3",
	}

	if !cp.Validate(claims) {
		t.Error("expected true")
	}
}

func TestParseOrWithEmbeddedAnyClaimPredicate2(t *testing.T) {
	input := map[string]any{
		"or": []map[string]any{
			{
				"key": "value",
			},
			{
				"and": []map[string]any{
					{
						"key2": "value2",
					},
					{
						"key3": "value3",
					},
				},
			},
		},
	}

	cp := ParseClaimPredicates(input)

	claims := jwt.MapClaims{
		"key2": "value2",
		"key3": "value3",
	}

	if !cp.Validate(claims) {
		t.Error("expected true")
	}
}

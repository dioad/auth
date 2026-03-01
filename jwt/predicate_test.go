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
package jwt

import (
	"encoding/json"
	"fmt"
	"maps"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
	gojwt "github.com/golang-jwt/jwt/v5"
)

// ClaimsMapFromToken parses an unverified JWT and returns its payload claims as a map.
func ClaimsMapFromToken(tokenString string) (map[string]any, error) {
	token, _, err := new(gojwt.Parser).ParseUnverified(tokenString, gojwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parse token claims: %w", err)
	}

	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type %T", token.Claims)
	}

	out := make(map[string]any, len(claims))
	maps.Copy(out, claims)
	return out, nil
}

// CustomClaimsMapFromValidatedClaims converts ValidatedClaims.CustomClaims into a generic map.
func CustomClaimsMapFromValidatedClaims(vc *jwtvalidator.ValidatedClaims) (map[string]any, error) {
	if vc == nil || vc.CustomClaims == nil {
		return nil, nil
	}

	raw, err := json.Marshal(vc.CustomClaims)
	if err != nil {
		return nil, fmt.Errorf("marshal custom claims: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal custom claims: %w", err)
	}
	return claims, nil
}

// ResolveCustomClaimsMap returns a normalized custom-claims map for a validated token.
// It prefers structured validator custom claims and falls back to the JWT payload map.
func ResolveCustomClaimsMap(vc *jwtvalidator.ValidatedClaims, tokenString string) (map[string]any, error) {
	claims, err := CustomClaimsMapFromValidatedClaims(vc)
	if err == nil && len(claims) > 0 {
		return claims, nil
	}

	if tokenString == "" {
		return claims, err
	}

	fallbackClaims, fallbackErr := ClaimsMapFromToken(tokenString)
	if fallbackErr != nil {
		if err != nil {
			return nil, fmt.Errorf("%v; fallback parse token claims: %w", err, fallbackErr)
		}
		return nil, fallbackErr
	}
	return fallbackClaims, nil
}

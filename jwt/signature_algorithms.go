package jwt

import (
	"fmt"
	"strings"

	jwtvalidator "github.com/auth0/go-jwt-middleware/v3/validator"
)

var defaultSignatureAlgorithms = []jwtvalidator.SignatureAlgorithm{
	jwtvalidator.RS256,
	jwtvalidator.ES384,
}

// DefaultSignatureAlgorithms returns the repository default JWT signature
// algorithms in precedence order.
func DefaultSignatureAlgorithms() []jwtvalidator.SignatureAlgorithm {
	return append([]jwtvalidator.SignatureAlgorithm(nil), defaultSignatureAlgorithms...)
}

// ParseSignatureAlgorithm parses a configured algorithm string into a supported
// validator.SignatureAlgorithm.
func ParseSignatureAlgorithm(raw string) (jwtvalidator.SignatureAlgorithm, error) {
	normalized := strings.ToUpper(strings.TrimSpace(raw))
	switch normalized {
	case string(jwtvalidator.HS256):
		return jwtvalidator.HS256, nil
	case string(jwtvalidator.HS384):
		return jwtvalidator.HS384, nil
	case string(jwtvalidator.HS512):
		return jwtvalidator.HS512, nil
	case string(jwtvalidator.RS256):
		return jwtvalidator.RS256, nil
	case string(jwtvalidator.RS384):
		return jwtvalidator.RS384, nil
	case string(jwtvalidator.RS512):
		return jwtvalidator.RS512, nil
	case string(jwtvalidator.PS256):
		return jwtvalidator.PS256, nil
	case string(jwtvalidator.PS384):
		return jwtvalidator.PS384, nil
	case string(jwtvalidator.PS512):
		return jwtvalidator.PS512, nil
	case string(jwtvalidator.ES256):
		return jwtvalidator.ES256, nil
	case string(jwtvalidator.ES384):
		return jwtvalidator.ES384, nil
	case string(jwtvalidator.ES512):
		return jwtvalidator.ES512, nil
	case string(jwtvalidator.ES256K):
		return jwtvalidator.ES256K, nil
	case strings.ToUpper(string(jwtvalidator.EdDSA)):
		return jwtvalidator.EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported signature algorithm %q", raw)
	}
}

// ResolveSignatureAlgorithms resolves algorithm configuration from either the
// multi-value field, legacy single field, or provided defaults.
func ResolveSignatureAlgorithms(
	single string,
	multiple []string,
	defaults []jwtvalidator.SignatureAlgorithm,
) ([]jwtvalidator.SignatureAlgorithm, error) {
	if len(multiple) > 0 {
		resolved := make([]jwtvalidator.SignatureAlgorithm, 0, len(multiple))
		seen := make(map[jwtvalidator.SignatureAlgorithm]struct{}, len(multiple))
		for i, raw := range multiple {
			if strings.TrimSpace(raw) == "" {
				return nil, fmt.Errorf("signature_algorithms[%d] must not be empty", i)
			}
			algorithm, err := ParseSignatureAlgorithm(raw)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[algorithm]; ok {
				continue
			}
			seen[algorithm] = struct{}{}
			resolved = append(resolved, algorithm)
		}
		return resolved, nil
	}

	if strings.TrimSpace(single) != "" {
		algorithm, err := ParseSignatureAlgorithm(single)
		if err != nil {
			return nil, err
		}
		return []jwtvalidator.SignatureAlgorithm{algorithm}, nil
	}

	if len(defaults) == 0 {
		return nil, fmt.Errorf("no signature algorithms configured")
	}
	return append([]jwtvalidator.SignatureAlgorithm(nil), defaults...), nil
}

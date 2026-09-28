package jwt

import (
	"errors"
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

// signatureAlgorithmsByName maps the normalized (uppercased, trimmed) name of
// each supported algorithm to its typed constant.
var signatureAlgorithmsByName = map[string]jwtvalidator.SignatureAlgorithm{
	string(jwtvalidator.HS256):                  jwtvalidator.HS256,
	string(jwtvalidator.HS384):                  jwtvalidator.HS384,
	string(jwtvalidator.HS512):                  jwtvalidator.HS512,
	string(jwtvalidator.RS256):                  jwtvalidator.RS256,
	string(jwtvalidator.RS384):                  jwtvalidator.RS384,
	string(jwtvalidator.RS512):                  jwtvalidator.RS512,
	string(jwtvalidator.PS256):                  jwtvalidator.PS256,
	string(jwtvalidator.PS384):                  jwtvalidator.PS384,
	string(jwtvalidator.PS512):                  jwtvalidator.PS512,
	string(jwtvalidator.ES256):                  jwtvalidator.ES256,
	string(jwtvalidator.ES384):                  jwtvalidator.ES384,
	string(jwtvalidator.ES512):                  jwtvalidator.ES512,
	string(jwtvalidator.ES256K):                 jwtvalidator.ES256K,
	strings.ToUpper(string(jwtvalidator.EdDSA)): jwtvalidator.EdDSA,
}

// ParseSignatureAlgorithm parses a configured algorithm string into a supported
// validator.SignatureAlgorithm.
func ParseSignatureAlgorithm(raw string) (jwtvalidator.SignatureAlgorithm, error) {
	normalized := strings.ToUpper(strings.TrimSpace(raw))
	if alg, ok := signatureAlgorithmsByName[normalized]; ok {
		return alg, nil
	}
	return "", fmt.Errorf("unsupported signature algorithm %q", raw)
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
		return nil, errors.New("no signature algorithms configured")
	}
	return append([]jwtvalidator.SignatureAlgorithm(nil), defaults...), nil
}

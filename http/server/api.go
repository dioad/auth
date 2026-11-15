package server

import (
	"fmt"

	"github.com/dioad/auth"
	nethttp "github.com/dioad/net/http"

	"github.com/dioad/auth/http/middleware"
	"github.com/dioad/auth/oidc"
)

// APIMiddlewares returns the authentication half of an API's middleware
// chain, in order: bearer token validation against validators, then principal
// extraction with extractor. Token validation is left out when there are no
// validators, which is the allow-unauthenticated case, so every request
// reaches the principal extractor with no token.
//
// Put anything that must run before authentication, such as a header check,
// ahead of the result, and anything that needs the principal, such as a rate
// limiter keyed by principal, after it. opts are passed to OAuth2ValidatorHandler.
func APIMiddlewares(validators []oidc.ValidatorConfig, extractor auth.PrincipalExtractor, opts ...ValidatorHandlerOption) ([]nethttp.Middleware, error) {
	var chain []nethttp.Middleware
	if len(validators) > 0 {
		validate, err := OAuth2ValidatorHandler(validators, opts...)
		if err != nil {
			return nil, fmt.Errorf("building JWT middleware: %w", err)
		}
		chain = append(chain, validate)
	}
	return append(chain, middleware.PrincipalExtractionHandler(extractor)), nil
}

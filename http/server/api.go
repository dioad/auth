package server

import (
	"fmt"

	"github.com/dioad/auth"
	"github.com/dioad/net/authz"
	nethttp "github.com/dioad/net/http"

	"github.com/dioad/auth/http/authz/principal"
	"github.com/dioad/auth/http/middleware"
	"github.com/dioad/auth/oidc"
)

// APIOption configures APIMiddlewares. A ValidatorHandlerOption is an
// APIOption that configures the token validation step.
type APIOption interface {
	applyAPI(*apiOptions)
}

type apiOptions struct {
	validator []ValidatorHandlerOption
	acl       *authz.PrincipalACLConfig
}

func (o ValidatorHandlerOption) applyAPI(a *apiOptions) {
	a.validator = append(a.validator, o)
}

type apiOptionFunc func(*apiOptions)

func (f apiOptionFunc) applyAPI(a *apiOptions) { f(a) }

// WithPrincipalACL adds a last step that admits only the principals acl
// allows, by the subject of the validated token, and refuses those it denies.
// It is for an API that authorises by who the caller is rather than by role,
// for example one that always admits the owner of a resource. It needs a
// token validated ahead of it, so use it with validators.
func WithPrincipalACL(acl authz.PrincipalACLConfig) APIOption {
	return apiOptionFunc(func(a *apiOptions) { a.acl = &acl })
}

// APIMiddlewares returns the authentication half of an API's middleware
// chain, in order: bearer token validation against validators, then principal
// extraction with extractor, then, with WithPrincipalACL, the principal ACL.
// Token validation is left out when there are no validators, which is the
// allow-unauthenticated case, so every request reaches the principal extractor
// with no token. A nil extractor leaves extraction out, for an API that
// authorises with WithPrincipalACL and has no roles to extract.
//
// Put anything that must run before authentication, such as a header check or
// CORS, ahead of the result, and anything that needs the principal, such as a
// rate limiter keyed by principal, after it. Options that are
// ValidatorHandlerOptions are passed to OAuth2ValidatorHandler.
func APIMiddlewares(validators []oidc.ValidatorConfig, extractor auth.PrincipalExtractor, opts ...APIOption) ([]nethttp.Middleware, error) {
	var options apiOptions
	for _, opt := range opts {
		opt.applyAPI(&options)
	}

	var chain []nethttp.Middleware
	if len(validators) > 0 {
		validate, err := OAuth2ValidatorHandler(validators, options.validator...)
		if err != nil {
			return nil, fmt.Errorf("building JWT middleware: %w", err)
		}
		chain = append(chain, validate)
	}
	if extractor != nil {
		chain = append(chain, middleware.PrincipalExtractionHandler(extractor))
	}
	if options.acl != nil {
		chain = append(chain, principal.NewHandler(*options.acl).Wrap)
	}
	return chain, nil
}

package jwt

import (
	"context"
	"net/http"
	"strings"

	"github.com/dioad/auth/jwt"
)

// ClaimsAuthoriser checks if the request satisfies a claim predicate.
type ClaimsAuthoriser struct {
	Predicate jwt.ClaimPredicate
}

// Create middleware that checks if request satisfies the predicate
func (a *ClaimsAuthoriser) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Placeholder: In a real implementation, we'd extract MapClaims from context
		// and use a.Predicate.Validate(claims)
		next.ServeHTTP(w, r)
	})
}

// ResourceAuthoriser handles resource-level permissions (scopes).
type ResourceAuthoriser struct {
	Service       string
	DefaultAction string
}

type Scope struct {
	Service  string
	Resource string
	Action   string
}

func (s *Scope) String() string {
	return strings.Join([]string{s.Service, s.Resource, s.Action}, ":")
}

func (a *ResourceAuthoriser) RequireScope(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scopes, ok := ScopesFromContext(r.Context())
			if !ok {
				http.Error(w, "Unauthorized: no scopes found", http.StatusUnauthorized)
				return
			}

			targetScope := &Scope{
				Service:  a.Service,
				Resource: resource,
				Action:   action,
			}

			if !ScopesMatch(scopes, targetScope) {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func ScopesMatch(subjects []*Scope, target *Scope) bool {
	for _, subject := range subjects {
		if ScopeMatch(subject, target) {
			return true
		}
	}
	return false
}

func ScopeMatch(subject, target *Scope) bool {
	if subject.Service != "*" && subject.Service != target.Service {
		return false
	}
	if subject.Resource != "*" && subject.Resource != target.Resource {
		return false
	}
	if subject.Action != "*" && subject.Action != target.Action {
		return false
	}
	return true
}

// Helper types/functions for context management
type contextServiceScopesKey struct{}

func ScopesFromContext(ctx context.Context) ([]*Scope, bool) {
	s, ok := ctx.Value(contextServiceScopesKey{}).([]*Scope)
	return s, ok
}

func NewContextWithScopes(ctx context.Context, scopes []*Scope) context.Context {
	return context.WithValue(ctx, contextServiceScopesKey{}, scopes)
}

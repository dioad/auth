package jwt

import (
	"fmt"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ClaimPredicate defines an interface for validating JWT claims.
type ClaimPredicate interface {
	Validate(input jwt.MapClaims) bool
	String() string
}

// And combines the children with an AND
func And(children ...ClaimPredicate) ClaimPredicate {
	return &andPredicate{Children: children}
}

// Or combines the children with an OR
func Or(children ...ClaimPredicate) ClaimPredicate {
	return &orPredicate{Children: children}
}

type andPredicate struct {
	Children []ClaimPredicate
}

func (a *andPredicate) Validate(claims jwt.MapClaims) bool {
	if len(a.Children) == 0 {
		return true
	}
	for _, child := range a.Children {
		if !child.Validate(claims) {
			return false
		}
	}
	return true
}

func (a *andPredicate) String() string {
	childrenStrings := make([]string, len(a.Children))
	for i, child := range a.Children {
		childrenStrings[i] = child.String()
	}
	return strings.Join(childrenStrings, " AND ")
}

type orPredicate struct {
	Children []ClaimPredicate
}

func (o *orPredicate) Validate(claims jwt.MapClaims) bool {
	if len(o.Children) == 0 {
		return false
	}
	for _, child := range o.Children {
		if child.Validate(claims) {
			return true
		}
	}
	return false
}

func (o *orPredicate) String() string {
	childrenStrings := make([]string, len(o.Children))
	for i, child := range o.Children {
		childrenStrings[i] = child.String()
	}
	return strings.Join(childrenStrings, " OR ")
}

// ClaimKey is a claim key predicate
type ClaimKey struct {
	Key   string
	Value any
}

func (c *ClaimKey) Validate(claims jwt.MapClaims) bool {
	if v, ok := claims[c.Key]; ok {
		switch v := v.(type) {
		case []any:
			return slices.Contains(v, c.Value)
		default:
			return v == c.Value
		}
	}
	return false
}

func (c *ClaimKey) String() string {
	return fmt.Sprintf("%s == %v", c.Key, c.Value)
}

type staticPredicate struct {
	result bool
}

func (p *staticPredicate) Validate(_ jwt.MapClaims) bool {
	return p.result
}

func (p *staticPredicate) String() string {
	return fmt.Sprintf("%v", p.result)
}

// ParseClaimPredicates parses the input into a claim predicate
func ParseClaimPredicates(input any) ClaimPredicate {
	switch v := input.(type) {
	case map[string]any:
		return parseClaimPredicateMap(v)
	case []any:
		return parseClaimPredicateList(v, And)
	default:
		return &staticPredicate{result: true}
	}
}

func parseClaimPredicateList(predicateList []any, combine func(...ClaimPredicate) ClaimPredicate) ClaimPredicate {
	result := make([]ClaimPredicate, 0, len(predicateList))
	for _, predicate := range predicateList {
		if p, ok := predicate.(map[string]any); ok {
			result = append(result, ParseClaimPredicates(p))
		}
	}
	return combine(result...)
}

func parseClaimPredicateMap(predicateMap map[string]any) ClaimPredicate {
	if len(predicateMap) == 0 {
		return &staticPredicate{result: true}
	}

	predicates := make([]ClaimPredicate, 0, len(predicateMap))
	for key, value := range predicateMap {
		switch key {
		case "and":
			if children, ok := value.([]any); ok {
				predicates = append(predicates, parseClaimPredicateList(children, And))
			}
		case "or":
			if children, ok := value.([]any); ok {
				predicates = append(predicates, parseClaimPredicateList(children, Or))
			}
		default:
			predicates = append(predicates, &ClaimKey{
				Key:   key,
				Value: value,
			})
		}
	}

	return And(predicates...)
}

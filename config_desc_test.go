package auth_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dioad/auth/authz"
	"github.com/dioad/auth/claimrolemapping"
	authhttp "github.com/dioad/auth/http"
	"github.com/dioad/auth/http/basic"
	"github.com/dioad/auth/http/browsersession"
	"github.com/dioad/auth/http/github"
	"github.com/dioad/auth/http/hmac"
	oidcmw "github.com/dioad/auth/http/middleware/oidc"
	"github.com/dioad/auth/http/server"
	"github.com/dioad/auth/jwt"
	"github.com/dioad/auth/oidc"
)

// Test_configStructs_flagsAreDescribed checks that every configuration
// property has the usage text dioad/cli prints in --help, or is kept off the
// command line with flag:"-" or flag:",hidden".
func Test_configStructs_flagsAreDescribed(t *testing.T) {
	t.Parallel()

	roots := []reflect.Type{
		reflect.TypeFor[authz.AuthorizerConfig](),
		reflect.TypeFor[claimrolemapping.ExtractorConfig](),
		reflect.TypeFor[authhttp.ClientConfig](),
		reflect.TypeFor[authhttp.ServerConfig](),
		reflect.TypeFor[authhttp.GenericAuthConfig](),
		reflect.TypeFor[basic.ClientConfig](),
		reflect.TypeFor[basic.ServerConfig](),
		reflect.TypeFor[browsersession.App](),
		reflect.TypeFor[github.ClientConfig](),
		reflect.TypeFor[github.ServerConfig](),
		reflect.TypeFor[hmac.ClientConfig](),
		reflect.TypeFor[hmac.ServerConfig](),
		reflect.TypeFor[oidcmw.OIDCConfig](),
		reflect.TypeFor[oidcmw.BrowserConfig](),
		reflect.TypeFor[server.RateLimitConfig](),
		reflect.TypeFor[jwt.ValidatorConfig](),
		reflect.TypeFor[oidc.ClientConfig](),
		reflect.TypeFor[oidc.ValidatorConfig](),
		reflect.TypeFor[oidc.TrustConfig](),
		reflect.TypeFor[oidc.Config](),
	}

	seen := map[reflect.Type]bool{}
	for _, root := range roots {
		for _, missing := range undescribedFields(root, seen) {
			assert.Failf(t, "config field has no usage text", "%s: add a desc tag, or flag:\"-\" / flag:\",hidden\"", missing)
		}
	}
}

// undescribedFields returns the names of the leaf fields reachable from t that
// have a mapstructure key but neither a desc tag nor a flag opt-out.
func undescribedFields(t reflect.Type, seen map[reflect.Type]bool) []string {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	// Types from other modules, such as dioad/net's TLS config, are described there.
	if t.Kind() != reflect.Struct || seen[t] || !strings.HasPrefix(t.PkgPath(), "github.com/dioad/auth") {
		return nil
	}
	seen[t] = true

	var missing []string
	for field := range t.Fields() {
		if !field.IsExported() {
			continue
		}
		tag, configured := field.Tag.Lookup("mapstructure")
		key, _, _ := strings.Cut(tag, ",")
		if !configured || key == "-" {
			continue
		}

		if isGroupingStruct(field.Type) {
			missing = append(missing, undescribedFields(field.Type, seen)...)
			continue
		}

		if field.Tag.Get("desc") != "" || flagOptedOut(field) {
			continue
		}
		missing = append(missing, t.String()+"."+field.Name)
	}
	return missing
}

// isGroupingStruct reports whether a field only groups other fields, so its
// children carry the usage text rather than the field itself.
func isGroupingStruct(t reflect.Type) bool {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	return t.Kind() == reflect.Struct && t.PkgPath() != "time"
}

func flagOptedOut(field reflect.StructField) bool {
	name, opts, _ := strings.Cut(field.Tag.Get("flag"), ",")
	if name == "-" {
		return true
	}
	for opt := range strings.SplitSeq(opts, ",") {
		if opt == "hidden" {
			return true
		}
	}
	return false
}

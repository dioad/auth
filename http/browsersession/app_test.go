package browsersession_test

import (
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dioad/auth/http/browsersession"
	oidcmw "github.com/dioad/auth/http/middleware/oidc"
)

func validAppConfig() browsersession.Config {
	return browsersession.Config{
		OIDC: oidcmw.BrowserConfig{
			Issuer:       "https://idp.example",
			ClientID:     "console",
			ClientSecret: "console-secret",
			RedirectURI:  "https://console.example/auth/callback",
			CookieSecure: true,
		},
		CookieEncryptionKey: strings.Repeat("0f", 32),
	}
}

func TestNewApp_Validation(t *testing.T) {
	t.Parallel()

	api := http.NotFoundHandler()
	staticFS := fstest.MapFS{"index.html": {Data: []byte("app")}}

	tests := []struct {
		name   string
		mutate func(*browsersession.Config)
		api    http.Handler
		fs     fstest.MapFS
	}{
		{name: "no encryption key", mutate: func(c *browsersession.Config) { c.CookieEncryptionKey = "" }},
		{name: "short encryption key", mutate: func(c *browsersession.Config) { c.CookieEncryptionKey = "0f0f" }},
		{name: "insecure cookies", mutate: func(c *browsersession.Config) { c.OIDC.CookieSecure = false }},
		{name: "no client secret", mutate: func(c *browsersession.Config) { c.OIDC.ClientSecret = "" }},
		{name: "no redirect uri", mutate: func(c *browsersession.Config) { c.OIDC.RedirectURI = "" }},
		{name: "no api handler", api: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validAppConfig()
			handler := api
			if tt.mutate != nil {
				tt.mutate(&cfg)
			} else {
				handler = tt.api
			}

			app, err := browsersession.NewApp(cfg, handler, staticFS)
			require.Error(t, err)
			assert.Nil(t, app)
		})
	}
}

func TestNewApp_Valid(t *testing.T) {
	t.Parallel()

	app, err := browsersession.NewApp(validAppConfig(), http.NotFoundHandler(), fstest.MapFS{"index.html": {Data: []byte("app")}})
	require.NoError(t, err)
	assert.NotNil(t, app.Auth)
	assert.NotNil(t, app.UI)
	assert.NotNil(t, app.API)
}

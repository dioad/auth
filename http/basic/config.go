package basic

// ClientConfig configures HTTP Basic credentials for an outgoing client,
// either directly (User/Password) or via a netrc file.
type ClientConfig struct {
	// https://everything.curl.dev/usingcurl/netrc
	//
	// machine connect.lab.dioad.net
	// login blah
	// password blah
	NetRCFile string `mapstructure:"netrc-file" desc:"path to a netrc file holding the credentials"`
	User      string `mapstructure:"user" desc:"user name"`
	Password  string `mapstructure:"password" desc:"password"`
}

// ServerConfig configures HTTP Basic authentication for a server.
type ServerConfig struct {
	AllowInsecureHTTP bool     `mapstructure:"allow-insecure-http" desc:"allow basic authentication over plain HTTP, for local development only"`
	HTPasswdFile      string   `mapstructure:"htpasswd-file" desc:"path to an htpasswd file of accepted credentials"`
	Users             []string `mapstructure:"users" desc:"accepted credentials as user:hash entries"`
	Realm             string   `mapstructure:"realm" desc:"realm sent in the authentication challenge"`
	// Throttle limits failed logins per client address. It is enabled by
	// default; see ThrottleConfig for the limits.
	Throttle ThrottleConfig `mapstructure:"throttle"`
}

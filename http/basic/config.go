package basic

// ClientConfig configures HTTP Basic credentials for an outgoing client,
// either directly (User/Password) or via a netrc file.
type ClientConfig struct {
	// https://everything.curl.dev/usingcurl/netrc
	//
	// machine connect.lab.dioad.net
	// login blah
	// password blah
	NetRCFile string `mapstructure:"netrc-file"`
	User      string `mapstructure:"user"`
	Password  string `mapstructure:"password"`
}

// ServerConfig configures HTTP Basic authentication for a server.
type ServerConfig struct {
	AllowInsecureHTTP bool     `mapstructure:"allow-insecure-http"`
	HTPasswdFile      string   `mapstructure:"htpasswd-file"`
	Users             []string `mapstructure:"users"`
	Realm             string   `mapstructure:"realm"`
}

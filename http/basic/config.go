package basic

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

type ServerConfig struct {
	AllowInsecureHTTP bool     `mapstructure:"allow-insecure-http"`
	HTPasswdFile      string   `mapstructure:"htpasswd-file"`
	Users             []string `mapstructure:"users"`
	Realm             string   `mapstructure:"realm"`
}

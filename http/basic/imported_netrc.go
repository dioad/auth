// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Imported from https://golang.org/src/cmd/go/internal/auth/netrc.go
package basic

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

type netrcLine struct {
	machine  string
	login    string
	password string
}

// NetrcProvider manages netrc credentials and their loading.
// It encapsulates the state for loading and parsing netrc files,
// allowing for multiple independent instances with different configurations.
// This resolves the global state issue that made testing difficult.
type NetrcProvider struct {
	once  sync.Once
	lines []netrcLine
	err   error
}

var (
	// defaultNetrcProvider is the package-level default provider for backward compatibility.
	defaultNetrcProvider = &NetrcProvider{}
)

func parseNetrc(data string) []netrcLine {
	// See https://www.gnu.org/software/inetutils/manual/html_node/The-_002enetrc-file.html
	// for documentation on the .netrc format.
	var nrc []netrcLine
	var l netrcLine
	inMacro := false
	for line := range strings.SplitSeq(data, "\n") {
		if inMacro {
			if line == "" {
				inMacro = false
			}
			continue
		}

		f := strings.Fields(line)
		i := 0
		for ; i < len(f)-1; i += 2 {
			// Reset at each "machine" token.
			// “The auto-login process searches the .netrc file for a machine token
			// that matches […]. Once a match is made, the subsequent .netrc tokens
			// are processed, stopping when the end of file is reached or another
			// machine or a default token is encountered.”
			switch f[i] {
			case "machine":
				l = netrcLine{machine: f[i+1]}
			case "default":
				break
			case "login":
				l.login = f[i+1]
			case "password":
				l.password = f[i+1]
			case "macdef":
				// “A macro is defined with the specified name; its contents begin with
				// the next .netrc line and continue until a null line (consecutive
				// new-line characters) is encountered.”
				inMacro = true
			}
			if l.machine != "" && l.login != "" && l.password != "" {
				nrc = append(nrc, l)
				l = netrcLine{}
			}
		}

		if i < len(f) && f[i] == "default" {
			// “There can be only one default token, and it must be after all machine tokens.”
			break
		}
	}

	return nrc
}

func netrcPath() (string, error) {
	if env := os.Getenv("NETRC"); env != "" {
		return env, nil
	}
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	base := ".netrc"
	if runtime.GOOS == "windows" {
		base = "_netrc"
	}
	return filepath.Join(dir, base), nil
}

// readNetrc reads and parses the netrc file for this provider.
func (p *NetrcProvider) readNetrc() {
	path, err := netrcPath()
	if err != nil {
		p.err = err
		return
	}

	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		if !os.IsNotExist(err) {
			p.err = err
		}
		return
	}

	p.lines = parseNetrc(string(data))
}

// NewNetrcProviderFromContent creates a NetrcProvider initialized with the given netrc content.
// This is useful for testing or when netrc data comes from a non-standard source.
func NewNetrcProviderFromContent(content string) *NetrcProvider {
	p := &NetrcProvider{}
	p.once.Do(func() {
		p.lines = parseNetrc(content)
	})
	return p
}

// Following imported from https://golang.org/src/cmd/go/internal/auth/auth.go

// AddCredentialsWithProvider fills in the user's credentials for req using the specified provider.
// The return value reports whether any matching credentials were found.
func AddCredentialsWithProvider(req *http.Request, provider *NetrcProvider) (added bool) {
	host := req.URL.Hostname()

	provider.once.Do(provider.readNetrc)
	for _, l := range provider.lines {
		if l.machine == host {
			req.SetBasicAuth(l.login, l.password)
			return true
		}
	}

	return false
}

// AddCredentials fills in the user's credentials for req, if any.
// The return value reports whether any matching credentials were found.
// This function uses the default package-level NetrcProvider for backward compatibility.
func AddCredentials(req *http.Request) (added bool) {
	return AddCredentialsWithProvider(req, defaultNetrcProvider)
}

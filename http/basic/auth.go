package basic

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/bcrypt"
)

// BasicAuthPair holds a username and its bcrypt-hashed password.
//
//nolint:revive // stutters, but is used externally (e.g. dioad/connect) as basic.BasicAuthPair; renaming is a breaking change
type BasicAuthPair struct {
	User           string
	HashedPassword string
}

// NewBasicAuthPairWithPlainPassword hashes password and returns a BasicAuthPair for user.
func NewBasicAuthPairWithPlainPassword(user, password string) (BasicAuthPair, error) {
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return BasicAuthPair{}, err
	}

	return BasicAuthPair{User: user, HashedPassword: hashedPassword}, nil
}

// VerifyPassword reports whether password matches p's stored hash.
func (p BasicAuthPair) VerifyPassword(password string) (bool, error) {
	byteHash := []byte(p.HashedPassword)
	err := bcrypt.CompareHashAndPassword(byteHash, []byte(password))
	if err != nil {
		return false, err
	}

	return true, nil
}

// ClientAuth adds HTTP Basic credentials to outgoing requests, resolving
// them from Config or, failing that, a netrc file.
type ClientAuth struct {
	Config        ClientConfig
	user          string
	password      string
	netrcProvider *NetrcProvider
}

// HTTPClient returns an *http.Client that authenticates every request with a's credentials.
func (a *ClientAuth) HTTPClient() *http.Client {
	return &http.Client{
		Transport: &RoundTripper{
			Username: a.user,
			Password: a.password,
		},
	}
}

// AddAuth sets the Basic auth header on req, resolving credentials from
// a.Config.User/Password or, if unset, the matching netrc entry for req's host.
func (a *ClientAuth) AddAuth(req *http.Request) error {
	// Initialize netrcProvider if not set
	if a.netrcProvider == nil {
		a.netrcProvider = &NetrcProvider{}
	}

	if a.user == "" {
		if a.Config.User != "" {
			a.user = a.Config.User
			a.password = a.Config.Password
		} else {
			host := req.URL.Hostname()

			a.netrcProvider.once.Do(a.netrcProvider.readNetrc)
			for _, l := range a.netrcProvider.lines {
				if l.machine == host {
					a.user = l.login
					a.password = l.password
					break
				}
			}
		}
	}
	req.SetBasicAuth(a.user, a.password)
	return nil
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// LoadBasicAuthFromFile reads an htpasswd-style file at filePath into an
// AuthMap. The file must be readable only by its owner (mode 0600 or 0400).
func LoadBasicAuthFromFile(filePath string) (AuthMap, error) {
	expFilePath, err := homedir.Expand(filePath)
	if err != nil {
		return nil, err
	}
	filePathClean := filepath.Clean(expFilePath)
	// #nosec G304
	f, err := os.Open(filePathClean)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Mode() != 0600 && stat.Mode() != 0400 {
		return nil, fmt.Errorf("error: basic auth file permissions are too open %v for %s, should be 0600 or 0400", stat.Mode(), filePathClean)
	}
	authMap := LoadBasicAuthFromReader(f)

	if err := f.Close(); err != nil {
		return authMap, fmt.Errorf("failed to close basic auth file %s: %w", filePathClean, err)
	}

	return authMap, nil
}

// LoadBasicAuthFromFileOrEmpty behaves like LoadBasicAuthFromFile, except a
// missing file returns an empty AuthMap and a nil error instead of the
// underlying os.Open error. Other errors (bad permissions, unreadable file)
// are returned unchanged. Useful for callers that treat "no credentials file
// yet" as a valid, empty starting state rather than a failure.
func LoadBasicAuthFromFileOrEmpty(filePath string) (AuthMap, error) {
	authMap, err := LoadBasicAuthFromFile(filePath)
	if errors.Is(err, fs.ErrNotExist) {
		return AuthMap{}, nil
	}
	return authMap, err
}

// LoadBasicAuthFromReader reads htpasswd-style "user:hash" lines from reader into an AuthMap.
func LoadBasicAuthFromReader(reader io.Reader) AuthMap {
	scanner := bufio.NewScanner(reader)

	return LoadBasicAuthFromScanner(scanner)
}

// LoadBasicAuthFromScanner reads htpasswd-style "user:hash" lines from scanner into an AuthMap.
func LoadBasicAuthFromScanner(scanner *bufio.Scanner) AuthMap {
	userMap := make(AuthMap)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		userMap.AddUserWithHashedPassword(parts[0], parts[1])
	}
	return userMap
}

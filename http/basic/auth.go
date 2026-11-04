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
	authMap, parseErr := parseBasicAuth(bufio.NewScanner(f))

	if err := f.Close(); err != nil {
		return authMap, fmt.Errorf("failed to close basic auth file %s: %w", filePathClean, err)
	}
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse basic auth file %s: %w", filePathClean, parseErr)
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

// ErrMalformedLine is returned by LoadBasicAuthFromFile for a line that is
// not blank, not a "#" comment, and not of the form "user:hash" with both
// parts non-empty.
var ErrMalformedLine = errors.New("malformed basic auth line")

// LoadBasicAuthFromReader reads htpasswd-style "user:hash" lines from reader
// into an AuthMap. Blank lines and "#" comments are ignored; malformed lines
// are skipped. Use LoadBasicAuthFromFile to have them reported instead.
func LoadBasicAuthFromReader(reader io.Reader) AuthMap {
	scanner := bufio.NewScanner(reader)

	return LoadBasicAuthFromScanner(scanner)
}

// LoadBasicAuthFromScanner reads htpasswd-style "user:hash" lines from
// scanner into an AuthMap. Blank lines and "#" comments are ignored;
// malformed lines are skipped.
func LoadBasicAuthFromScanner(scanner *bufio.Scanner) AuthMap {
	userMap := make(AuthMap)
	for scanner.Scan() {
		if user, hash, ok := parseLine(scanner.Text()); ok {
			userMap.AddUserWithHashedPassword(user, hash)
		}
	}
	return userMap
}

// parseBasicAuth reads htpasswd-style lines like LoadBasicAuthFromScanner,
// but fails on the first malformed line, naming its line number, and on a
// read error.
func parseBasicAuth(scanner *bufio.Scanner) (AuthMap, error) {
	userMap := make(AuthMap)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if isIgnorableLine(line) {
			continue
		}
		user, hash, ok := parseLine(line)
		if !ok {
			return nil, fmt.Errorf("line %d: %w", lineNumber, ErrMalformedLine)
		}
		userMap.AddUserWithHashedPassword(user, hash)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return userMap, nil
}

// parseLine splits a "user:hash" line. It reports false for blank lines,
// comments, and lines missing either part.
func parseLine(line string) (string, string, bool) {
	if isIgnorableLine(line) {
		return "", "", false
	}
	user, hash, found := strings.Cut(strings.TrimSpace(line), ":")
	if !found || user == "" || hash == "" {
		return "", "", false
	}
	return user, hash, true
}

func isIgnorableLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#")
}

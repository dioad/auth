package basic

import (
	"bufio"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var (
	SingleLine = `userA:$2y$10$fTk4TDw95prvkXxFD1bfge.vtKt/QhCmeH5bZTqMx4gSSjA9rlETS`
	MultiLine  = `userA:$2y$10$fTk4TDw95prvkXxFD1bfge.vtKt/QhCmeH5bZTqMx4gSSjA9rlETS
userB:$2y$10$oLAH9Nt949RBaRQB5ThTd./kZFGfrvtVYgsaHnbgkkgHbSSYK9jMi`
)

func testCompare(t *testing.T, basicAuth BasicAuthPair, password string) {
	_, err := basicAuth.VerifyPassword(password)
	if err != nil {
		t.Errorf("password comparison failed: %v", err)
	}
}

func TestBasicAuthCompare(t *testing.T) {
	basicAuth := BasicAuthPair{"userA", "$2y$10$fTk4TDw95prvkXxFD1bfge.vtKt/QhCmeH5bZTqMx4gSSjA9rlETS"}

	testCompare(t, basicAuth, "passwordA")
}

func TestBasicAuthWithPlainPasswordCompare(t *testing.T) {
	basicAuth, _ := NewBasicAuthPairWithPlainPassword("userA", "passwordA")

	testCompare(t, basicAuth, "passwordA")
}

func TestLoadBasicAuthFromScanner(t *testing.T) {
	tests := map[string]struct {
		input         string
		mapLength     int
		checkUser     string
		checkPassword string
	}{
		"single line": {input: SingleLine, mapLength: 1, checkUser: "userA", checkPassword: "passwordA"},
		"multi line":  {input: MultiLine, mapLength: 2, checkUser: "userB", checkPassword: "passwordB"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			scanner := bufio.NewScanner(strings.NewReader(tc.input))
			userMap := LoadBasicAuthFromScanner(scanner)
			diff := cmp.Diff(tc.mapLength, len(userMap))
			if diff != "" {
				t.Fatal(diff)
			}

			valid, _ := userMap.Authenticate(tc.checkUser, tc.checkPassword)
			if !valid {
				t.Fatalf("unable to authenticate %s with %s", tc.checkUser, tc.checkPassword)
			}
		})
	}
}

package basic

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseNetrc_MacroEndsOnlyOnBlankLine is the regression test for the
// macro-termination guard: a macro body continues until a genuinely blank
// line, not merely a non-empty one. The fixture's macro body spans three
// non-blank lines -- a dummy line, then "login"/"password" tokens that
// would otherwise complete a bogus credential triple if the macro ended
// after just the first body line.
func TestParseNetrc_MacroEndsOnlyOnBlankLine(t *testing.T) {
	data := `machine macrotest.host macdef mymacro
dummyline
login bogus
password alsobogus

machine real.host
login realuser
password realpass
`
	lines := parseNetrc(data)
	assert.Equal(t, []netrcLine{{"real.host", "realuser", "realpass"}}, lines,
		"the macro body's login/password tokens must not leak out as a real credential entry")
}

// TestParseNetrc_OddFieldCountDoesNotOverrunFields is the regression test
// for the field-pairing loop bound (i < len(f)-1). A line with an odd
// number of fields leaves one trailing, unpaired token; the loop must stop
// before it. The trailing token here is itself a recognized keyword
// ("login") with no following value, so an off-by-one that lets the loop
// process it anyway indexes one past the end of the field slice.
func TestParseNetrc_OddFieldCountDoesNotOverrunFields(t *testing.T) {
	data := `machine stray login u1 password p1 login
machine after.stray
login u2
password p2
`
	require.NotPanics(t, func() {
		lines := parseNetrc(data)
		assert.Equal(t, []netrcLine{
			{"stray", "u1", "p1"},
			{"after.stray", "u2", "p2"},
		}, lines)
	})
}

// TestParseNetrc_RequiresMachineBeforeLoginAndPassword is the regression
// test for the "all three fields set" guard requiring a non-empty machine:
// a login/password pair with no preceding "machine" token must not be
// captured as a credential entry with an empty machine name.
func TestParseNetrc_RequiresMachineBeforeLoginAndPassword(t *testing.T) {
	data := `login orphanuser
password orphanpass
`
	lines := parseNetrc(data)
	assert.Empty(t, lines, "a login/password pair with no machine token must not produce an entry")
}

// TestParseNetrc_StepsByFieldPairsNotSingleFields is the regression test
// for the loop's increment (i += 2): the field-pairing loop must advance
// by whole key/value pairs. A login value that happens to be the literal
// word "machine" only exposes a step-by-1 bug, since a step-by-1 loop
// would revisit that value position as if it were a key, treating it as a
// fresh "machine" token and corrupting the entry -- ordinary alternating
// key/value data can't tell the two step sizes apart, since the odd
// (value) positions a step-by-1 loop additionally visits don't match any
// recognized keyword and are silently no-ops.
func TestParseNetrc_StepsByFieldPairsNotSingleFields(t *testing.T) {
	data := "machine tricky login machine password pwd\n"

	lines := parseNetrc(data)
	assert.Equal(t, []netrcLine{{"tricky", "machine", "pwd"}}, lines)
}

// TestParseNetrc_ResetsAfterEachCompleteEntry is the regression test for
// clearing the working entry after each append: without it, a stale
// machine/login/password value from a just-appended entry can persist and
// get re-appended as a bogus duplicate when a later token (redefining
// login/password without a fresh "machine" token) momentarily leaves all
// three fields looking non-empty again.
func TestParseNetrc_ResetsAfterEachCompleteEntry(t *testing.T) {
	data := "machine a login u1 password p1 login u2 password p2\n"

	lines := parseNetrc(data)
	assert.Equal(t, []netrcLine{{"a", "u1", "p1"}}, lines,
		"redefining login/password without a fresh machine token must not produce another entry")
}

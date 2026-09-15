package hmac

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorAfterNBytesReader yields data normally for its first n bytes, then
// returns a non-EOF error on any subsequent read -- used to reach the
// "probe read past the limit" error path, distinct from that read simply
// hitting a clean EOF.
type errorAfterNBytesReader struct {
	data []byte
	pos  int
}

func (r *errorAfterNBytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("simulated read error past body end")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *errorAfterNBytesReader) Close() error { return nil }

// onceErrorThenEOFReader errors on its first Read call, then reports a
// clean io.EOF on every call after that -- used to distinguish the initial
// bounded read's own error guard from the later probe read's, since a
// reader that errors identically on every call can't tell the two guards
// apart (removing either one still surfaces the same error via the other).
type onceErrorThenEOFReader struct {
	called bool
}

func (r *onceErrorThenEOFReader) Read([]byte) (int, error) {
	if !r.called {
		r.called = true
		return 0, errors.New("simulated first-read error")
	}
	return 0, io.EOF
}

func (r *onceErrorThenEOFReader) Close() error { return nil }

func TestReadAndValidateBody_NilBodyReturnsEmpty(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Body = nil

	body, err := readAndValidateBody(r, 1024)
	require.NoError(t, err)
	assert.Equal(t, []byte{}, body)
}

func TestReadAndValidateBody_ReadsAndRestoresBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("payload"))

	body, err := readAndValidateBody(r, 1024)
	require.NoError(t, err)
	assert.Equal(t, []byte("payload"), body)

	restored, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(restored), "the body must be restored for the handler to read again")
}

// TestReadAndValidateBody_PropagatesReadError covers the initial bounded
// read's own error guard. The reader errors only once (on the read the
// limited-read/io.ReadAll call makes) and returns a clean EOF on the later
// probe read, so removing this guard would let the probe read observe EOF
// and the function would incorrectly succeed instead of propagating the
// error.
func TestReadAndValidateBody_PropagatesReadError(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Body = &onceErrorThenEOFReader{}

	_, err := readAndValidateBody(r, 1024)
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to read request body")
}

// TestReadAndValidateBody_PropagatesProbeReadError covers the second,
// separate read used to detect a body larger than the limit: a body of
// exactly maxSize bytes lets the first (limited) read succeed cleanly
// without exhausting the underlying reader, so the probe read is the one
// that hits the underlying reader's error -- distinguishing it from a
// plain io.EOF, which is the expected/valid outcome at exactly the limit.
func TestReadAndValidateBody_PropagatesProbeReadError(t *testing.T) {
	const limit = 8
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Body = &errorAfterNBytesReader{data: bytes.Repeat([]byte("a"), limit)}

	_, err := readAndValidateBody(r, limit)
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to read request body")
}

// TestReadAndValidateBody_RejectsBodyExactlyOneByteOverLimit is the
// regression test for the extra-byte size-limit probe: at exactly maxSize
// bytes, the body must be accepted; at maxSize+1, the same call must
// reject it. Both share the same io.LimitedReader read of exactly maxSize
// bytes, so only the ExactLimit/OverLimit pair together can distinguish
// the probe read's own off-by-one from a genuinely correct boundary.
func TestReadAndValidateBody_RejectsBodyExactlyOneByteOverLimit(t *testing.T) {
	const limit = 8

	atLimit := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bytes.Repeat([]byte("a"), limit)))
	body, err := readAndValidateBody(atLimit, limit)
	require.NoError(t, err)
	assert.Len(t, body, limit)

	overLimit := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bytes.Repeat([]byte("a"), limit+1)))
	_, err = readAndValidateBody(overLimit, limit)
	require.Error(t, err)
	assert.ErrorContains(t, err, "exceeds maximum size limit")
}

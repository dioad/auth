package basic

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newThrottledHandler(t *testing.T, cfg ThrottleConfig) (*Handler, *fakeClock) {
	t.Helper()
	h, err := NewHandlerWithMap(ServerConfig{Throttle: cfg}, newTestAuthMap(t, "right"))
	require.NoError(t, err)
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	h.throttle.now = clock.Now
	return h, clock
}

func loginFrom(h *Handler, addr, user, pass string) error {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = addr
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	_, err := h.AuthRequest(req)
	return err
}

func TestHandler_Throttle_LocksOutAfterMaxFailures(t *testing.T) {
	t.Parallel()
	h, _ := newThrottledHandler(t, ThrottleConfig{MaxFailures: 3})

	for range 3 {
		err := loginFrom(h, "192.0.2.1:1000", "alice", "wrong")
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrThrottled)
	}

	err := loginFrom(h, "192.0.2.1:1000", "alice", "right")
	require.ErrorIs(t, err, ErrThrottled, "right password must be rejected while locked out")
}

func TestHandler_Throttle_IsPerClientAddressIgnoringPort(t *testing.T) {
	t.Parallel()
	h, _ := newThrottledHandler(t, ThrottleConfig{MaxFailures: 2})

	require.Error(t, loginFrom(h, "192.0.2.1:1000", "alice", "wrong"))
	require.Error(t, loginFrom(h, "192.0.2.1:2000", "alice", "wrong"))

	require.ErrorIs(t, loginFrom(h, "192.0.2.1:3000", "alice", "right"), ErrThrottled)
	assert.NoError(t, loginFrom(h, "192.0.2.2:1000", "alice", "right"), "other addresses are unaffected")
}

func TestHandler_Throttle_LockoutExpires(t *testing.T) {
	t.Parallel()
	h, clock := newThrottledHandler(t, ThrottleConfig{MaxFailures: 1, Lockout: time.Minute})

	require.Error(t, loginFrom(h, "192.0.2.1:1", "alice", "wrong"))
	require.ErrorIs(t, loginFrom(h, "192.0.2.1:1", "alice", "right"), ErrThrottled)

	clock.Advance(time.Minute + time.Second)

	assert.NoError(t, loginFrom(h, "192.0.2.1:1", "alice", "right"))
}

func TestHandler_Throttle_FailuresExpireWithWindow(t *testing.T) {
	t.Parallel()
	h, clock := newThrottledHandler(t, ThrottleConfig{MaxFailures: 2, Window: time.Minute})

	require.Error(t, loginFrom(h, "192.0.2.1:1", "alice", "wrong"))
	clock.Advance(2 * time.Minute)
	require.Error(t, loginFrom(h, "192.0.2.1:1", "alice", "wrong"))

	assert.NoError(t, loginFrom(h, "192.0.2.1:1", "alice", "right"), "stale failure must not count towards the limit")
}

func TestHandler_Throttle_SuccessClearsFailures(t *testing.T) {
	t.Parallel()
	h, _ := newThrottledHandler(t, ThrottleConfig{MaxFailures: 2})

	require.Error(t, loginFrom(h, "192.0.2.1:1", "alice", "wrong"))
	require.NoError(t, loginFrom(h, "192.0.2.1:1", "alice", "right"))
	require.Error(t, loginFrom(h, "192.0.2.1:1", "alice", "wrong"))

	assert.NoError(t, loginFrom(h, "192.0.2.1:1", "alice", "right"))
}

func TestHandler_Throttle_MissingCredentialsAreNeutral(t *testing.T) {
	t.Parallel()
	h, _ := newThrottledHandler(t, ThrottleConfig{MaxFailures: 2})

	require.Error(t, loginFrom(h, "192.0.2.1:1", "alice", "wrong"))
	for range 5 {
		err := loginFrom(h, "192.0.2.1:1", "", "")
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrThrottled)
	}

	assert.NoError(t, loginFrom(h, "192.0.2.1:1", "alice", "right"), "challenge requests must not count as failures")
}

func TestHandler_Throttle_Disabled(t *testing.T) {
	t.Parallel()
	h, err := NewHandlerWithMap(ServerConfig{Throttle: ThrottleConfig{Disabled: true, MaxFailures: 1}}, newTestAuthMap(t, "right"))
	require.NoError(t, err)

	for range 3 {
		require.Error(t, loginFrom(h, "192.0.2.1:1", "alice", "wrong"))
	}

	assert.NoError(t, loginFrom(h, "192.0.2.1:1", "alice", "right"))
}

func TestHandler_Throttle_WrapRespondsWith429AndRetryAfter(t *testing.T) {
	t.Parallel()
	h, _ := newThrottledHandler(t, ThrottleConfig{MaxFailures: 1, Lockout: 90 * time.Second})
	wrapped := h.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func(pass string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.0.2.1:1"
		req.SetBasicAuth("alice", pass)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		return rec
	}

	assert.Equal(t, http.StatusUnauthorized, do("wrong").Code)

	rec := do("right")
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	retryAfter, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	require.NoError(t, err)
	assert.Equal(t, 90, retryAfter)
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"))
}

func TestThrottle_TableIsBounded(t *testing.T) {
	t.Parallel()
	th := newThrottle(ThrottleConfig{}, time.Now)

	for i := range maxThrottleEntries + 100 {
		th.recordFailure("client-" + strconv.Itoa(i))
	}

	assert.LessOrEqual(t, len(th.entries), maxThrottleEntries)
}

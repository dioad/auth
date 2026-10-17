package basic

import (
	"errors"
	"net"
	"sync"
	"time"
)

// Defaults applied to ThrottleConfig fields left at their zero value.
const (
	DefaultThrottleMaxFailures = 10
	DefaultThrottleWindow      = 5 * time.Minute
	DefaultThrottleLockout     = 5 * time.Minute

	// maxThrottleEntries bounds the number of client addresses tracked at once.
	maxThrottleEntries = 10000
)

// ErrThrottled is returned by Handler.AuthRequest when the client address has
// made too many failed login attempts. Use errors.As with *ThrottledError to
// obtain the retry delay.
var ErrThrottled = errors.New("too many failed login attempts")

// ThrottledError carries how long a locked-out client must wait to retry.
type ThrottledError struct {
	RetryAfter time.Duration
}

// Error implements error.
func (e *ThrottledError) Error() string {
	return ErrThrottled.Error()
}

// Is reports whether target is ErrThrottled.
func (e *ThrottledError) Is(target error) bool {
	return target == ErrThrottled
}

// ThrottleConfig limits failed logins per client address to slow down
// password guessing. Throttling is enabled unless Disabled is set.
type ThrottleConfig struct {
	// Disabled turns failed-login throttling off. By default throttling is on.
	Disabled bool `mapstructure:"disabled"`
	// MaxFailures is the number of rejected logins allowed within Window
	// before the client address is locked out. Defaults to 10.
	MaxFailures int `mapstructure:"max-failures"`
	// Window is how long a failed login counts towards MaxFailures. Defaults
	// to 5 minutes.
	Window time.Duration `mapstructure:"window"`
	// Lockout is how long a client address is rejected with 429 once
	// MaxFailures is reached, even if it then supplies the right password.
	// Defaults to 5 minutes.
	Lockout time.Duration `mapstructure:"lockout"`
}

type throttleEntry struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

// throttle tracks failed logins per client address. The table is bounded and
// expired entries are pruned as it fills.
type throttle struct {
	maxFailures int
	window      time.Duration
	lockout     time.Duration
	now         func() time.Time

	mu      sync.Mutex
	entries map[string]*throttleEntry
}

func newThrottle(cfg ThrottleConfig, now func() time.Time) *throttle {
	if cfg.Disabled {
		return nil
	}
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = DefaultThrottleMaxFailures
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultThrottleWindow
	}
	if cfg.Lockout <= 0 {
		cfg.Lockout = DefaultThrottleLockout
	}
	return &throttle{
		maxFailures: cfg.MaxFailures,
		window:      cfg.Window,
		lockout:     cfg.Lockout,
		now:         now,
		entries:     make(map[string]*throttleEntry),
	}
}

// clientKey returns the host part of remoteAddr. X-Forwarded-For is
// deliberately not trusted: it is client-controlled unless a trusted proxy
// overwrites it.
func clientKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// check returns a *ThrottledError if key is currently locked out.
func (t *throttle) check(key string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[key]
	if !ok {
		return nil
	}
	now := t.now()
	if now.Before(e.lockedUntil) {
		return &ThrottledError{RetryAfter: e.lockedUntil.Sub(now)}
	}
	return nil
}

// recordFailure counts a rejected login for key, locking it out when the
// limit is reached.
func (t *throttle) recordFailure(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	e, ok := t.entries[key]
	if !ok {
		t.makeRoom(now)
		e = &throttleEntry{windowStart: now}
		t.entries[key] = e
	}
	if now.Sub(e.windowStart) > t.window && !now.Before(e.lockedUntil) {
		e.failures = 0
		e.windowStart = now
	}
	e.failures++
	if e.failures >= t.maxFailures {
		e.lockedUntil = now.Add(t.lockout)
		e.failures = 0
		e.windowStart = now
	}
}

// recordSuccess clears the failure history for key.
func (t *throttle) recordSuccess(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// makeRoom prunes expired entries, and if the table is still full evicts the
// entry whose window started earliest. Callers must hold t.mu.
func (t *throttle) makeRoom(now time.Time) {
	if len(t.entries) < maxThrottleEntries {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, e := range t.entries {
		if now.Sub(e.windowStart) > t.window && !now.Before(e.lockedUntil) {
			delete(t.entries, k)
			continue
		}
		if oldestKey == "" || e.windowStart.Before(oldest) {
			oldestKey, oldest = k, e.windowStart
		}
	}
	if len(t.entries) >= maxThrottleEntries {
		delete(t.entries, oldestKey)
	}
}

---
description: 'Structured logging conventions using zerolog across HTTP handlers, middleware, and library code'
applyTo: '**/*.go'
---

# Structured Logging with zerolog

All logging uses `github.com/rs/zerolog`. Follow these conventions consistently across every package and codebase.

## Core Rule: Request-Scoped vs Construction-Time Loggers

The choice of where a logger lives determines how log events are correlated:

| Context | Pattern | Reason |
|---------|---------|--------|
| `net/http` handler or middleware | `zerolog.Ctx(r.Context())` | Carries request-scoped fields (request ID, auth info) through the full handler chain |
| Long-lived struct with fixed enrichment | `zerolog.Logger` field on the struct | Carries construction-time labels (component name, validator label) that never change |
| Program startup / `main()` | `log.Logger` (package-level) | No request context exists; acceptable at the outermost layer only |

Never store a `zerolog.Logger` on a struct that handles `net/http` requests just to avoid writing `zerolog.Ctx(r.Context())`. The stored logger will not carry dynamic request fields, and those fields will be silently absent from every log event.

## HTTP Handlers

Always obtain the logger from the request context:

```go
// Correct
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    log := zerolog.Ctx(r.Context())
    log.Error().Err(err).Msg("token exchange failed")
}

// Correct — inline for single use
zerolog.Ctx(r.Context()).Error().Err(err).Msg("failed to generate state")

// Wrong — stored logger misses request-scoped fields
type Handler struct {
    logger zerolog.Logger // do not do this for HTTP handlers
}
```

`zerolog.Ctx` returns a no-op logger when no logger is in the context — it is always safe to call without a nil check.

For handlers that call the logger more than once, assign a short-lived local:

```go
log := zerolog.Ctx(r.Context())
if code == "" {
    log.Error().Msg("missing code in callback")
    http.Error(w, "missing code", http.StatusBadRequest)
    return
}
if state == "" {
    log.Error().Msg("missing state in callback")
    http.Error(w, "missing state", http.StatusBadRequest)
    return
}
```

## Middleware: Enrich the Context Logger with UpdateContext

Middleware that authenticates, enriches, or categorises a request should add structured fields to the context logger using `UpdateContext`. Fields added this way are present in all subsequent log events for the request — including deferred access log entries written after the handler returns.

```go
// Add a field unconditionally when auth succeeds
zerolog.Ctx(r.Context()).UpdateContext(func(c zerolog.Context) zerolog.Context {
    return c.Str("auth_source", "oidc_session")
})

// Add a field conditionally (e.g. only when a token was refreshed)
if refreshed {
    zerolog.Ctx(r.Context()).UpdateContext(func(c zerolog.Context) zerolog.Context {
        return c.Bool("token_refreshed", true)
    })
}

// Pass the enriched context to the next handler
next.ServeHTTP(w, r.WithContext(ctx))
```

`UpdateContext` mutates the logger stored in the context in-place. There is no need to create a new context or reassign `r` solely for the logger update; the mutation is visible to all code that subsequently calls `zerolog.Ctx` on the same context.

### Do Not Pass Loggers as Function Arguments to HTTP Handlers

Middleware and handlers should not accept a `zerolog.Logger` parameter for per-request logging. Use `zerolog.Ctx(r.Context())` inside the handler body. Passing a logger as an argument bypasses context-scoped enrichment.

```go
// Wrong
func NewHandler(validator Validator, cookieName string, logger zerolog.Logger) *Handler

// Correct
func NewHandler(validator Validator, cookieName string) *Handler
```

## Handlers: Add Extracted Identifiers to Context

Any HTTP handler that extracts an identifier or meaningful scope value from the request — path value, query parameter, or decoded body field — must add it to the context logger via `UpdateContext` as early as possible, so that all subsequent log events for the request automatically carry it. This includes deferred access log entries written after the handler returns.

```go
// Path value
tunnelID := req.PathValue("tunnelID")
zerolog.Ctx(req.Context()).UpdateContext(func(c zerolog.Context) zerolog.Context {
    return c.Str("tunnel_id", tunnelID)
})

// Body field (after decoding)
zerolog.Ctx(req.Context()).UpdateContext(func(c zerolog.Context) zerolog.Context {
    return c.Str("target_state", body.State)
})

// Multiple fields in one call
zerolog.Ctx(req.Context()).UpdateContext(func(c zerolog.Context) zerolog.Context {
    return c.
        Str("request_id", tc.RequestID).
        Str("connection_id", tc.ConnectionID.String()).
        Str("direction_type", string(cfg.DirectionType))
})
```

Add `UpdateContext` before any log events or calls to downstream handlers, so the fields are present in every event — not just the ones written after the update.

### What to add

Add identifiers and resource-scope labels that are safe to record for every request:

- **Path values** — resource identifiers such as `tunnel_id`, `provider`, `connection_id`
- **Non-sensitive body fields** — discriminators and state labels such as `tunnel_type`, `target_state`
- **Configuration scope** — fields that characterise the request class such as `service_type`, `direction_type`

### What NOT to add

Never add security-sensitive values to the context logger:

- OAuth `code` or `state` query parameters
- Passwords, API keys, shared secrets, HMAC signatures
- Session tokens, refresh tokens, or any bearer credential
- PII beyond what is already present via `principal` (e.g. full email addresses, raw claims)

When in doubt: if the value would be redacted in a security audit, do not log it.

### Deduplication across middleware layers

Some fields (`principal`, `auth_source`, `token_refreshed`) are already added to context by upstream middleware. Do not repeat them in downstream handlers — check what the middleware chain for the current handler sets before adding a field.

## Field Naming: Always snake_case

All log field names must use `snake_case`. This applies to both `Str`/`Bool`/`Int` calls in handlers and to fields added by `UpdateContext`.

```go
// Correct
log.Str("auth_source", "oidc_session")
log.Bool("token_refreshed", true)
log.Str("request_id", id)
log.Int("jwt_validators", count)

// Wrong — mixed naming breaks query consistency in log aggregation tools
log.Str("authSource", "oidc_session")    // camelCase
log.Bool("TokenRefreshed", true)         // PascalCase
log.Str("request-id", id)               // kebab-case
```

### Standard Field Names

Use these names consistently across all codebases:

| Field | Type | Set by | Meaning |
|-------|------|--------|---------|
| `request_id` | `string` | Request-ID middleware | Unique ID per HTTP request |
| `auth_source` | `string` | Auth middleware | Which auth mechanism validated the request (`oidc_session`, `jwt`, `basic`, `github`, `hmac`) |
| `token_refreshed` | `bool` | OIDC session middleware | Set to `true` when a token was silently refreshed during the request |
| `component` | `string` | Construction-time | Subsystem label (e.g. `cors`, `proxy`) |

## Log Messages

- Use sentence case; start messages with a capital letter
- Keep messages lowercase — they are machine-readable strings, not prose
- Never end a message with punctuation
- Do not interpolate dynamic values into the message string; put them in typed fields

```go
// Correct
log.Error().Err(err).Msg("failed to refresh token")
log.Error().Err(err).Str("cookie", name).Msg("missing or invalid state cookie")

// Wrong
log.Error().Msgf("failed to refresh token: %v", err)  // swallows structured err field
log.Error().Msg("Failed to refresh token.")            // capital + punctuation
```

## Construction-Time Loggers

Validators, debuggers, and other long-lived components that carry a fixed label (e.g. the name of the OIDC issuer being validated) may hold a `zerolog.Logger` as a struct field. This is correct because the enrichment is set once at construction, not per-request.

```go
type ValidatorDebugger struct {
    inner  TokenValidator
    logger zerolog.Logger  // acceptable: enriched once with a fixed label
}

func NewValidatorDebugger(v TokenValidator, opts ...Option) *ValidatorDebugger {
    d := &ValidatorDebugger{inner: v, logger: zerolog.Nop()}
    for _, opt := range opts {
        opt(d)
    }
    return d
}

func WithLogger(l zerolog.Logger) Option {
    return func(d *ValidatorDebugger) { d.logger = l }
}
```

The key distinction: if the log enrichment is the same for every call (e.g. `label:"flyio"`), a stored logger is appropriate. If the enrichment depends on the in-flight request (e.g. `request_id`, `auth_source`), use `zerolog.Ctx`.

## Testing

Use `zerolog.Nop()` for construction-time loggers in tests:

```go
d := NewValidatorDebugger(validator, WithLogger(zerolog.Nop()))
```

For handlers and middleware under test, inject a logger into the request context:

```go
logger := zerolog.New(os.Stderr)
ctx := logger.WithContext(context.Background())
req = req.WithContext(ctx)
```

Or use `zerolog.Nop()` to suppress output in unit tests where log content is not being asserted:

```go
ctx := zerolog.Nop().WithContext(context.Background())
req = req.WithContext(ctx)
```

## Summary of Anti-Patterns

| Anti-pattern | Correct alternative |
|---|---|
| `logger zerolog.Logger` field on an HTTP handler struct | `zerolog.Ctx(r.Context())` in the handler body |
| Passing `zerolog.Logger` as an argument to handler constructors | Remove the parameter; read from context at call time |
| Using `log.Logger` (package-level) inside a handler | `zerolog.Ctx(r.Context())` |
| camelCase or PascalCase field names | `snake_case` field names |
| `log.Msgf(...)` with `%v` for errors | `.Err(err).Msg(...)` to preserve structured error fields |
| Logging an error and then returning it | Choose one: log it here, or return it and let the caller log it |
| `UpdateContext` fields added after calling `next.ServeHTTP` | Add `UpdateContext` fields before calling `next.ServeHTTP` so they are present in the handler and in deferred access logs |

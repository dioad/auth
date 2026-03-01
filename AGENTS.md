# AGENTS.md - Go Project Guidelines

This document outlines the essential checks that must pass before any task is considered complete and provides guidelines for generating idiomatic Go code within this project.

## Pre-completion Checks

Before a task is marked as complete, the following Go commands *must* execute successfully without errors or warnings. These checks ensure code quality, correctness, and adherence to project standards.

1.  **`go build ./...`**
    *   **Purpose:** This command compiles all packages in the module. A successful execution indicates that the code is syntactically correct and all dependencies can be resolved, producing executable or compiled packages as appropriate.
    *   **Requirement:** The build process must complete without any compilation errors.

2.  **`go vet ./...`**
    *   **Purpose:** `go vet` examines Go source code and reports suspicious constructs, such as `printf` format errors, `struct` tags, and unkeyed composite literals. It helps to identify potential bugs and code smells that might not be caught by the compiler.
    *   **Requirement:** `go vet` must report no issues. Any reported issues must be addressed or explicitly justified if they are false positives.

3.  **`go test -race ./...`**
    *   **Purpose:** This command runs the tests for the specified packages and enables the data race detector. The race detector helps identify concurrency bugs where multiple goroutines access the same variable concurrently without proper synchronization, and at least one of the accesses is a write.
    *   **Requirement:** All tests must pass, and the race detector must report no data races. This is crucial for robust concurrent applications.

4.  **`shellcheck -o all <script.sh>`**
    *   **Purpose:** `shellcheck` is a static analysis tool for shell scripts that identifies bugs, potential issues, and style improvements. Enabling all checks with `-o all` ensures maximum script quality and robustness.
    *   **Requirement:** All shell scripts (e.g., in `test-scripts/`) must be linted using `shellcheck -o all` and all identified issues must be addressed.

## Idiomatic Go Generated Code Rules

Generated code should adhere to the following principles to maintain consistency, readability, and Go best practices. The goal is for generated code to be indistinguishable from hand-written idiomatic Go code.

1.  **Formatting (`gofmt`):**
    *   All generated code *must* be formatted using `gofmt`. This ensures consistent style across the entire codebase.

2.  **Naming Conventions:**
    *   **Public (Exported) Elements:** Use `CamelCase` (e.g., `MyStruct`, `MyFunction`).
    *   **Private (Unexported) Elements:** Use `camelCase` (e.g., `myStruct`, `myFunction`).
    *   **Acronyms:** Acronyms should be all uppercase in exported names (e.g., `HTTPClient`, `JSONMarshal`), and all lowercase in unexported names (e.g., `httpClient`, `jsonMarshal`).
    *   **Interface Names:** Short, descriptive, often ending with "er" (e.g., `Reader`, `Writer`, `Manager`).

3.  **Error Handling:**
    *   **Explicit Error Checks:** Always check for errors returned by functions. Do not ignore them.
    *   **Error Wrapping:** Use `fmt.Errorf("message: %w", err)` to wrap errors, preserving the original error context. This allows for programmatic inspection using `errors.Is` and `errors.As`.
    *   **Custom Error Types:** Define custom error types for specific, expected error conditions when it benefits API consumers (e.g., `ErrNotFound`, `ErrInvalidInput`).
    *   **Clear Error Messages:** Error messages should be informative and actionable for the user or developer.

4.  **Context (`context.Context`):**
    *   Functions that perform I/O operations, interact with external services, or are long-running/cancellable *must* accept `context.Context` as their first argument.
    *   Propagate the context through function calls.

5.  **Concurrency:**
    *   Use goroutines and channels for concurrent operations.
    *   Utilize `sync.WaitGroup` for waiting on multiple goroutines to complete.
    *   Avoid shared mutable state where possible. If necessary, protect with `sync.Mutex` or `sync.RWMutex`.
    *   Avoid global mutable state.

6.  **Imports:**
    *   Organize imports into standard Go library, then third-party libraries, then internal project packages, each in separate groups.
    *   Use blank imports (`_`) only for side effects (e.g., registering a `driver`).

7.  **Comments (`Godoc`):**
    *   All exported (public) types, functions, methods, and constants *must* have clear and concise Godoc comments.
    *   Comments should explain *what* the element does, *why* it exists, its parameters, and what it returns (if applicable).
    *   Internal (unexported) elements should have comments when their purpose is not immediately obvious from the code.

8.  **Package Design:**
    *   Packages should be small, focused, and have a single responsibility.
    *   Exported APIs should be minimal and clear, following the principle of least surprise.

9.  **Generics (Go 1.18+):**
    *   Use generics when they genuinely improve code reuse, type safety, and readability without adding unnecessary complexity. Avoid using generics for the sake of it.

10. **Security:**
    *   Generated code should follow secure coding practices, including input validation, avoiding hardcoded credentials, and using secure defaults for configurations (e.g., TLS).

## Example Generation Guidelines

Examples are an essential part of API documentation and should be created as executable, maintainable code artifacts rather than embedded markdown snippets. Follow the Go standard [example conventions](https://go.dev/blog/examples) when generating examples.

### Example Approach

**Small Examples (Simple API Interactions):**
- Small examples demonstrating basic type interactions or single function calls are acceptable in `README.md` or package-level documentation.
- Keep these focused on a single concept and no more than 10-15 lines of code.

**Larger Examples (Standalone Executables):**
- Create standalone executable programs in the `examples/` directory for comprehensive examples.
- These examples must be complete programs with `package main` and `func main()` that users can build and run.
- When adding new features or major functionality, create a corresponding example in `examples/` (e.g., `examples/my-feature/main.go`).
- All examples in the `examples/` directory are automatically built as part of the CI workflow.

**Examples Directory Structure:**
- Each feature area should have its own subdirectory under `examples/` (e.g., `examples/basic-http-server/`, `examples/oidc-auth/`)
- Each subdirectory should contain a `main.go` file with a complete, runnable program
- Examples should be fully executable with `go run` or by building with `go build`
- Include a `README.md` in each example directory with instructions on how to run the example

### Running Examples

Examples can be run directly with `go run`:
```bash
go run github.com/dioad/net/examples/basic-http-server
```

Or by building and running the executable:
```bash
cd examples/basic-http-server
go build
./basic-http-server
```

### Best Practices

- **Realistic Use Cases:** Examples should reflect actual usage patterns that users might encounter
- **Error Handling:** Include proper error handling to demonstrate correct API usage
- **Comments:** Add explanatory comments for non-obvious behavior; the example itself should be mostly self-documenting
- **Graceful Shutdown:** For server examples, include proper signal handling for graceful shutdown
- **Complete Programs:** Examples should be complete, runnable programs that users can immediately use
- **README Files:** Each example directory should include a README.md with:
  - Brief description of what the example demonstrates
  - Instructions on how to run the example
  - Any prerequisites or special requirements
  - Example commands to test the running program

## GitHub Actions Guidelines

1.  **Linux-Based Commands:**
    *   GitHub Actions workflows in this project run on Linux runners.
    *   All commands, shell scripts, and parameters inserted into workflow files *must* be compatible with Linux (GNU/Linux).
    *   Avoid macOS-specific CLI flags or behaviors (e.g., `sed`, `grep`, `find`). Always prefer the GNU/Linux syntax for GitHub Actions.

## Documentation

### README.md Maintenance

The `README.md` file provides an overview of the library's capabilities and serves as the primary entry point for users. Any changes that affect the public API, add new features, or modify existing behavior **must** include corresponding updates to `README.md`.

**Documentation Updates are Required When:**
- Adding new packages or major features
- Changing the public API of exported types or functions
- Adding new authentication or authorization methods
- Modifying server behavior or configuration options
- Adding integration examples (Fly.io, GitHub Actions, etc.)
- Removing deprecated features

**Documentation Updates Should Include:**
- Summary of the change or new feature
- Quick start example if applicable
- Links to relevant package documentation
- Any new package structure updates
- Updated requirements if dependencies changed

**Process:**
1. Update code with the feature or fix
2. Update `README.md` with corresponding documentation
3. Ensure examples are accurate and tested
4. Run `go build ./...` and `go test -race ./...` to verify changes compile and tests pass
5. Commit code and documentation together

### Documentation Style

- Use clear, concise language
- Provide practical examples over theoretical explanations
- Organize features by user benefit (e.g., "🔐 Authentication & Authorization")
- Link to related packages and features
- Keep the Quick Start section up-to-date and tested
- Document breaking changes prominently

Following these guidelines ensures that generated code is maintainable, understandable, and integrates seamlessly with the rest of the Go project.

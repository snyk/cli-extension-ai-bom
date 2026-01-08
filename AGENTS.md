# Agent Guidelines

This document provides instructions and context for AI agents working in the `snyk-cli-extension-ai-bom` repository.

## 1. Environment & Commands

### Setup

Ensure all necessary tools are installed before running commands.

- **Install Tools**: `make install-tools`
  - This installs `golangci-lint`, `pre-commit`, and `mockgen`.

### Build & Run

- **Generate Code**: `make generate`
  - Runs `go generate ./...` (useful for mocks).

### Testing

- **Run All Tests**: `make test`
  - Executes `go test -v ./...`
- **Run Single Test**:
  - Use `go test -v ./internal/package/path -run TestName`
  - Example: `go test -v ./internal/services/red-team-client -run TestGetScan`
- **Test Dependencies**:
  - Uses `github.com/stretchr/testify` for assertions.
  - Uses `go.uber.org/mock/mockgen` for mocking interfaces.

### Linting & Formatting

- **Lint Code**: `make lint`
  - Runs `golangci-lint run -v ./...`
  - Strict linters are enabled (see `.golangci.yaml`).
- **Format Code**: `make format`
  - Runs `golangci-lint run --fix -v ./...`
  - Applies `gofumpt`, `goimports`, and other fixable linters.
  - **Always run this before committing.**

## 2. Code Style & Conventions

### General Go Style

- **Go Version**: 1.24+
- **Line Length**: Soft limit of 160 characters (enforced by `lll`).
- **Naming**:
  - Use `PascalCase` for exported types/functions.
  - Use `camelCase` for private types/functions/variables.
  - Acronyms should be consistent (e.g., `ID`, `URL`, `API`, `HTML`).

### Imports

- Imports must be grouped and ordered:
  1. Standard Library (`fmt`, `os`, etc.)
  2. Third-party packages (`github.com/google/uuid`, etc.)
  3. Internal/Project packages (`github.com/snyk/cli-extension-ai-bom/...`)
- **Tooling**: `goimports` is configured with `local-prefixes: github.com/snyk/cli-extension-ai-bom`.
- **Restriction**: Do not use `.` (dot) imports unless necessary (e.g., for `gomega` matchers if used, though `testify` is preferred).

### Error Handling

- **Custom Errors**:
  - Use `internal/errors` or `internal/errors/redteam` for domain-specific errors.
  - Errors often wrap `snyk_errors` from `github.com/snyk/error-catalog-golang-public`.
- **Wrapping**:
  - Always wrap errors when bubbling up: `fmt.Errorf("failed to do action: %w", err)`.
- **Messages**:
  - Error strings may start with capital letters (linter rules `stylecheck` ST1005 and `revive` error-strings are relaxed).
  - Messages should be descriptive and user-friendly where appropriate.
- **Checks**:
  - Explicitly check `if err != nil`.
  - Avoid ignoring errors (`_ = func()`) without a comment explaining why.

### Logging

- **Library**: Uses `github.com/rs/zerolog`.
- **Usage**:
  - Pass `*zerolog.Logger` as a dependency or extract from context if available.
  - Use structured logging: `logger.Debug().Str("key", "value").Err(err).Msg("message")`.
  - Avoid `fmt.Printf` for logging; use the logger.

### Context

- **Propagation**:
  - Pass `context.Context` as the first argument to functions performing I/O or long-running operations.
  - Respect context cancellation.

## 3. Project Structure

- `cmd/`: Entry points for the application.
- `internal/`: Private application code.
  - `commands/`: Implementation of CLI commands (e.g., `aibomcreate`, `redteam`).
  - `services/`: Business logic and external clients (`red-team-client`, `code`, `depgraph`).
  - `errors/`: Centralized error definitions.
  - `utils/`: Shared utility functions.
- `pkg/`: Library code that might be imported by other projects (if any).
- `mocks/`: Generated mock files.
- `scripts/`: Build and utility scripts.

## 4. Specific Patterns

### Snyk Extension Framework

- This project is a Snyk CLI extension using `github.com/snyk/go-application-framework`.
- Workflows are registered in `cmd/` or `internal/commands/`.
- Use `workflow.InvocationContext` to access configuration, logger, and UI.

### Red Team Client

- Located in `internal/services/red-team-client`.
- Follows the pattern: `ClientImpl` struct implementing `RedTeamClient` interface.
- Returns explicit custom error types (`*redteam_errors.RedTeamError`).
- Uses `http.Client` with custom redirect handling (`http.ErrUseLastResponse`).

### User Interface (TUI)

- Uses `github.com/charmbracelet/bubbletea` for interactive terminal UIs.
- TUI code is located in `internal/commands/redteam/tui/`.
- Follows the Model-View-Update (ELM) architecture.

## 5. Development Workflow for Agents

1.  **Analyze**:
    - Read `Makefile` and `CONTRIBUTING.md` (though this file summarizes them).
    - Search for existing patterns using `grep` or `glob`.
2.  **Edit**:
    - Apply changes adhering to the style guide.
    - If modifying an interface, remember to update mocks (`make generate`).
3.  **Verify**:
    - **Lint**: Run `make lint`. Fix any issues.
    - **Format**: Run `make format`.
    - **Test**: Run relevant tests. Write new tests for new functionality.
    - **Build**: Ensure the project compiles (`go build ./...`).

## 6. Linter Rules (Specifics)

The project uses strict linting via `.golangci.yaml`. Key configuration:

- **Enabled**: `gofumpt`, `revive`, `govet`, `staticcheck`, `errcheck`, `gocritic`, `gocyclo` (min-complexity 15), `lll` (160 chars).
- **Disabled Rules**:
  - `fieldalignment` (govet)
  - `blank-imports` (revive - disabled, meaning strict check is off? Verify if needed, usually best to avoid).
  - Error message capitalization rules are disabled to match Snyk standards.

## 7. Version Control

- **Commits**: Follow conventional commits (`feat:`, `fix:`, `chore:`, etc.).
- **Messages**: Concise, imperative mood.

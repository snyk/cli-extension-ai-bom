# AGENTS.md

This document provides context for AI coding assistants working on this codebase.

## Project Context

### What the Project Does
This is the **Snyk AI BOM CLI Extension**, a Go-based CLI extension that provides two main capabilities:
1. **AI BOM Generation** (`snyk aibom`) - Generates an AI Bill of Materials (AIBOM) document in CycloneDX format for local software projects, identifying AI-related components
2. **Red Team Scanning** (`snyk redteam`) - Runs red teaming security scans against LLM-based applications to identify vulnerabilities

### Target Users/Audience
- Internal Snyk development teams
- Snyk CLI users who need AI security scanning capabilities
- Security teams analyzing AI components in software projects

## Tech Stack

### Languages and Frameworks
- **Language**: Go 1.24.4
- **CLI Framework**: Snyk Go Application Framework (`github.com/snyk/go-application-framework`)
- **Flag Parsing**: `github.com/spf13/pflag`
- **Logging**: `github.com/rs/zerolog`
- **Validation**: `github.com/go-playground/validator/v10`
- **YAML Parsing**: `gopkg.in/yaml.v3`

### Testing Libraries
- **Test Framework**: `github.com/stretchr/testify`
- **Mocking**: `go.uber.org/mock` and `github.com/golang/mock`

### Key Dependencies
- `github.com/snyk/code-client-go` - Code analysis client
- `github.com/snyk/error-catalog-golang-public` - Standardized Snyk error types
- `github.com/google/uuid` - UUID generation for request tracking

## Architecture

### High-Level Overview
The project follows a layered architecture:
```
cmd/           → Entry points (development CLI)
pkg/           → Public initialization packages
internal/      → Private implementation
  commands/    → CLI command handlers (workflows)
  services/    → Business logic and external clients
  errors/      → Error type definitions
  utils/       → Shared utilities and constants
mocks/         → Generated mock implementations for testing
```

### Key Directories

| Directory | Purpose |
|-----------|---------|
| `cmd/develop/` | Development CLI entry point for local testing |
| `pkg/aibom/` | Public AIBOM workflow initialization |
| `pkg/redteam/` | Public Red Team workflow initialization |
| `internal/commands/aibomcreate/` | AIBOM generation command implementation |
| `internal/commands/redteam/` | Red team scanning command implementation |
| `internal/commands/redteamscanningagent/` | Red team scanning agent subcommand |
| `internal/services/ai-bom-client/` | HTTP client for AI BOM API |
| `internal/services/red-team-client/` | HTTP client for Red Team API |
| `internal/services/code/` | Code bundle upload service |
| `internal/services/depgraph/` | Dependency graph service |
| `internal/errors/` | Custom error types wrapping Snyk error catalog |
| `mocks/` | Mock implementations organized by package |

### Important Files

| File | Description |
|------|-------------|
| `internal/commands/aibomcreate/aibomcreate.go` | Main AIBOM workflow logic |
| `internal/commands/redteam/redteam.go` | Main Red Team workflow logic |
| `internal/utils/config.go` | Flag constants and configuration keys |
| `mocks/generate.go` | Mock generation directives |
| `.golangci.yaml` | Linter configuration (extensive rules) |

## Code Style & Conventions

### Naming Conventions
- **Packages**: Lowercase, single-word names (e.g., `aibomcreate`, `redteam`)
- **Interfaces**: PascalCase, typically ending with action verbs (e.g., `CodeService`, `AiBomClient`)
- **Structs**: PascalCase with `Impl` suffix for implementations (e.g., `AIBOMClientImpl`)
- **Constants**: PascalCase for exported, camelCase for unexported
- **Flags**: Use `FlagXxx` prefix for flag name constants (e.g., `FlagExperimental`)
- **Workflow IDs**: Use `workflow.NewWorkflowIdentifier("name")` pattern

### File Organization Patterns
- Commands live in `internal/commands/<command>/`
- Each command has: main implementation file, test file, and optional testdata
- Services live in `internal/services/<service-name>/`
- Service packages contain: `client.go`, `models.go`, `client_test.go`
- Mocks are in `mocks/<servicename>mock/`

### Import Ordering
Follow `goimports` with local prefix `github.com/snyk/cli-extension-ai-bom`:
1. Standard library
2. Third-party packages
3. Snyk packages (external)
4. Local packages (this repo)

Example:
```go
import (
    "context"
    "fmt"

    "github.com/rs/zerolog"
    "github.com/snyk/go-application-framework/pkg/workflow"

    "github.com/snyk/cli-extension-ai-bom/internal/errors"
    "github.com/snyk/cli-extension-ai-bom/internal/utils"
)
```

### Comment Style Preferences
- **Avoid inline comments** - only add comments when code is not self-explanatory
- **Don't add comments just because** - code should be readable without them
- Use `//nolint:lintername // reason` format when suppressing linter warnings (explanation required)
- Package comments are optional but enforced by revive

## Development Workflow

### Building and Running

```bash
# Install development tools (golangci-lint, pre-commit, mockgen)
make install-tools

# Run red team workflow locally
make redteam -- --help

# Build extension with CLI (requires CLI_PATH)
make build-cli CLI_PATH=/path/to/cli
```

### Running Tests

```bash
# Run all unit tests
make test

# Or directly with go
go test -v ./...
```

### Linting and Formatting

```bash
# Run linters
make lint

# Format code (auto-fix)
make format

# Generate mocks
make generate
```

### Pre-commit Hooks
The project uses pre-commit with:
- `gitleaks` - Secret scanning
- `commitlint` - Conventional commit message format
- `make format` and `make lint` - Code quality

## Patterns & Best Practices

### Workflow Pattern
Commands are implemented as Snyk workflows:
1. Register workflow with flags in `RegisterWorkflows()`
2. Implement entry point function that creates real dependencies
3. Implement testable `RunXxxWorkflow()` that accepts interfaces
4. Return `[]workflow.Data` for output

```go
func RegisterWorkflows(e workflow.Engine) error {
    flagset := pflag.NewFlagSet("name", pflag.ExitOnError)
    // Add flags...
    configuration := workflow.ConfigurationOptionsFromFlagset(flagset)
    _, err := e.Register(WorkflowID, configuration, workflowFunc)
    return err
}
```

### Dependency Injection
- Commands accept service interfaces, not concrete implementations
- This enables testing with mocks
- Real implementations are created in the workflow entry point

### Error Handling
- Use custom error types wrapping Snyk error catalog (`snyk_errors.Error`)
- `AiBomError` and `RedTeamError` wrapper types provide consistency
- Factory functions for each error type (e.g., `NewUnauthorizedError()`, `NewInternalError()`)
- Always log debug information before returning errors

```go
if err != nil {
    logger.Debug().Err(err).Msg("descriptive message")
    return nil, errors.NewInternalError("user-facing message")
}
```

### HTTP Client Pattern
- Create client struct with logger, httpClient, userAgent, baseURL
- Use `http.NewRequestWithContext()` for all requests
- Set common headers via helper method
- Return custom error types based on HTTP status codes

### Logging Practices
- Use `zerolog` via `invocationCtx.GetEnhancedLogger()`
- Log at `Debug` level for operational details
- Log at `Info` level for significant user-visible events
- Log at `Warn` level for recoverable issues
- Include structured fields: `.Str("field", value).Msg("message")`

### Testing Patterns
- Test files use `_test` package suffix (e.g., `package aibomcreate_test`)
- Use `gomock` for mocking interfaces
- Helper mock for InvocationContext in `mocks/frameworkmock/framework_mock.go`
- Test naming: `TestXxx_SCENARIO` (e.g., `TestAiBomWorkflow_HAPPY`)
- Use `testify/assert` for assertions

## AI Assistant Guidelines

### Things to Always Do
- Run `make lint` after making changes to ensure code quality
- Run `make test` to verify tests pass
- Follow the existing import ordering convention
- Use dependency injection for testable code
- Wrap errors using the custom error types from `internal/errors/`
- Add `//nolint` directives with explanations when suppressing linter warnings
- Use `context.Context` for cancellation and timeouts in HTTP operations
- Generate mocks with `make generate` when adding new interfaces

### Things to Avoid
- Don't add inline comments unless absolutely necessary for clarity
- Don't add comments "just because" - prefer self-documenting code
- Don't skip the `--experimental` flag check for experimental features
- Don't use `fmt.Errorf` directly - use error catalog types
- Don't create concrete dependencies in workflow functions - use interfaces
- Don't ignore linter warnings without documented reason
- Don't use `panic` - return errors instead
- Don't commit secrets or credentials (gitleaks will catch this)

### Project-Specific Rules
1. **Experimental Flag**: Both `aibom` and `redteam` commands require `--experimental` flag
2. **Organization ID**: Always validate `orgID` is present before API calls
3. **Progress Bars**: Use `ui.NewProgressBar()` for long-running operations, always `defer cleanup()`
4. **API Versioning**: Use `APIVersion` constant for REST API calls

### Linter Configuration Highlights
The project uses extensive linting (see `.golangci.yaml`):
- Max line length: 160 characters
- Max cyclomatic complexity: 15
- `gofumpt` with extra rules enabled
- `nolintlint` requires specific linter name and explanation
- `errcheck` requires checking all errors including type assertions
- Error messages may start with uppercase (ST1005 disabled for Snyk standards)

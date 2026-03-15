# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Commands

```bash
# Build
go build -o barry ./main.go

# Test
go test ./...

# Run a single test
go test ./internal/agents/... -run TestPipelineName

# Lint
golangci-lint run ./...

# Docker build
docker build -t barry .
```

## Architecture

Barry is an AI-powered GitHub Action that scans Pull Requests for security
vulnerabilities using Google Gemini and the
[ADK-Go](https://pkg.go.dev/google.golang.org/adk) framework.

### Multi-agent pipeline

```
GitHub PR → Scanner Agent → Hard Filter Agent → [Validator Agent] → [Autofixer Agent] → PR Comments / SARIF
```

1. **Scanner** (`internal/agents/scanner.go`) — Gemini Pro with structured
   output schema; outputs `ScanResult` stored in ADK session state as
   `raw_findings`
2. **Hard Filter** (`internal/agents/hardfilter.go`) — Pure Go, regex-based;
   reads `raw_findings`, writes `filtered_findings` + `hard_filter_stats`
3. **Validator** (`internal/agents/validator.go`) — Gemini Flash (optional);
   per-finding LLM re-examination; writes `validated_findings`
4. **Autofixer** (`internal/agents/autofixer.go`) — Gemini Pro (optional);
   generates code fixes; enriches findings with `Autofix` field

Pipeline is wired in `internal/agents/pipeline.go` using `adk.SequentialAgent`.

### Key packages

| Package | Purpose |
|---|---|
| `main.go` | Entrypoint: config loading, PR fetch, pipeline run, output/comments |
| `internal/config` | Parse `INPUT_*` env vars + GitHub event JSON |
| `internal/github` | GitHub API: fetch PR data, diff, post review comments |
| `internal/findings` | `Finding`/`ScanResult`/`ValidationResult` types + Gemini `ResponseSchema` definitions |
| `internal/filter` | Hard exclusion regex rules, file include/exclude logic, exception file loading |
| `internal/comment` | Format and batch-post PR review comments |
| `internal/sarif` | Generate SARIF reports for GitHub Security tab |
| `internal/prompts` | Embedded markdown prompt templates |

### Data flow in `main.go`

1. `config.Load()` — env vars + `$GITHUB_EVENT_PATH` JSON
2. GitHub client fetches PR files and unified diff
3. Files filtered by excluded directories (`internal/filter/files.go`)
4. `agents.BuildSecurityPrompt()` constructs the scanner prompt (with optional
   custom instructions)
5. `pipeline.Run()` executes the ADK sequential agent pipeline
6. Results written as JSON or SARIF; PR comments posted if
   `INPUT_COMMENT-PR=true`
7. Exit code 1 if any HIGH severity findings remain

### Structured output

Gemini is called with a `ResponseSchema` (defined in
`internal/findings/schema.go`) to guarantee valid JSON — no fragile regex
extraction. Each agent reads/writes typed structs through ADK session state.

### Running locally against a real PR

```bash
# Create event.json: {"pull_request": {"number": 123}}
GOOGLE_API_KEY="..." \
GITHUB_TOKEN="..." \
GITHUB_REPOSITORY="owner/repo" \
GITHUB_EVENT_PATH="./event.json" \
INPUT_COMMENT-PR="false" \
./barry
```

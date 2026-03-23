# Barry

<img src="barry-icon.svg" alt="Barry icon — Saint Bernard dog on a security shield" width="200"/>

AI-powered security code review for GitHub Pull Requests with autofix
suggestions, powered by Google Gemini and
[ADK-Go](https://google.github.io/adk-docs/).

Barry is a GitHub Action that automatically scans your PRs for security
vulnerabilities using a multi-agent pipeline:

1. **Scanner Agent** — Analyzes the PR diff with Gemini for security issues
2. **Hard Filter Agent** — Removes obvious false positives using deterministic
   regex rules
3. **Validator Agent** *(optional)* — Re-examines each finding with a second LLM
   pass to further reduce false positives
4. **Autofixer Agent** *(optional)* — Generates idiomatic code fixes for
   confirmed vulnerabilities

## Table of Contents

- [Quick Start](#quick-start)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [Architecture](#architecture)
  - [Hard Filter Rules](#hard-filter-rules)
- [Custom Instructions](#custom-instructions)
  - [Custom Security Scan Instructions](#custom-security-scan-instructions)
  - [Custom False Positive Filtering](#custom-false-positive-filtering)
- [GitHub Security Center Integration](#github-security-center-integration)
  - [Setup](#setup)
  - [Prerequisites](#prerequisites)
  - [Build](#build)
  - [Test](#test)
  - [Lint](#lint)
  - [Running Locally](#running-locally)
- [License](#license)

## Quick Start

```yaml
name: Security Review
on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  contents: read
  pull-requests: write

jobs:
  security-review:
    runs-on: ubuntu-latest
    environment: security-review
    steps:
      - uses: cosmin/barry@v1
        with:
          google-api-key: ${{ secrets.GOOGLE_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

> **Why `pull_request_target` and the `security-review` environment?**
>
> Barry needs a `GOOGLE_API_KEY` secret to call Gemini. With a plain
> `pull_request` trigger, GitHub does **not** expose repository secrets
> to workflows triggered by fork PRs — so Barry would fail on any
> external contribution.
>
> `pull_request_target` runs in the context of the **base** branch and
> has access to the repository's secrets. However, because it runs
> trusted workflow code against potentially untrusted PR content, it
> introduces a security risk. The `security-review`
> [environment](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment)
> acts as a gate: configure it with **required reviewers** so that a
> maintainer must approve each run before secrets are exposed to the
> workflow.

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `google-api-key` | Google API key for Gemini | *required* |
| `github-token` | GitHub token for PR access | *required* |
| `gemini-model` | Model for scanning | `gemini-3-flash-preview` |
| `validator-model` | Model for validation | `gemini-3-flash-preview` |
| `autofix-model` | Model for generating autofixes | `gemini-3-flash-preview` |
| `comment-pr` | Post findings as PR comments | `true` |
| `upload-results` | Upload results as artifact | `true` |
| `enable-llm-filtering` | Use LLM to validate findings | `true` |
| `enable-autofix` | Generate LLM-based autofixes | `true` |
| `exclude-directories` | Comma-separated dirs to skip | `""` |
| `timeout` | Timeout in minutes | `20` |
| `run-every-commit` | Run on every commit, not just first | `false` |
| `false-positive-filtering-instructions` | Path to custom filtering instructions file | `""` |
| `custom-security-scan-instructions` | Path to custom scan instructions file | `""` |
| `output-format` | Output format for results file: `json` or `sarif` | `json` |
| `output-dir` | Directory to write the results file | `$GITHUB_WORKSPACE` |
| `exceptions-file` | Path to a JSON file defining findings to exclude | `""` |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Number of findings after filtering |
| `results-file` | Path to the results file (JSON or SARIF depending on `output-format`) |

## Architecture

```
┌────────────────┐     ┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│    Scanner     │     │  Hard Filter   │     │   Validator    │     │   Autofixer    │
│   (Gemini)     │ ──▶ │    (Regex)     │ ──▶ │   (Gemini)     │ ──▶ │   (Gemini)     │
│                │     │                │     │  per-finding   │     │  per-finding   │
│  Structured    │     │ Deterministic  │     │   LLM check    │     │ code generation│
│  JSON output   │     │   exclusions   │     │   (optional)   │     │   (optional)   │
└────────────────┘     └────────────────┘     └────────────────┘     └────────────────┘
```

The Scanner and Hard Filter run as a **sequential agent** in ADK-Go. The
Validator and Autofixer run separately per-finding when `enable-llm-filtering`
and `enable-autofix` are true, respectively.

### Hard Filter Rules

The hard filter removes common false positive categories:
- **DOS/Resource exhaustion** — Generic denial of service findings
- **Rate limiting** — Missing rate limit recommendations
- **Resource leaks** — Memory/connection leak findings
- **Open redirects** — Low-impact redirect findings
- **Regex injection** — Regex-related findings
- **Memory safety** — Buffer overflow etc. in non-C/C++ code
- **SSRF in HTML** — Server-side findings in client-side code
- **Markdown files** — Any finding in documentation files

## Custom Instructions

### Custom Security Scan Instructions

Create a text file with additional categories to scan for:

```text
Check for:
- Hardcoded API keys or secrets in configuration files
- Insecure deserialization of user-controlled data
- Missing CSRF protection on state-changing endpoints
```

Reference it in your workflow:
```yaml
- uses: cosmin/barry@v1
  with:
    google-api-key: ${{ secrets.GOOGLE_API_KEY }}
    github-token: ${{ secrets.GITHUB_TOKEN }}
    custom-security-scan-instructions: .github/security-scan-instructions.txt
```

See [examples/custom-gosec-security-scan-instructions.txt][gosec-scan-ex] for
a full example targeting the [securego/gosec][gosec] project.

[gosec-scan-ex]: examples/custom-gosec-security-scan-instructions.txt

### Custom False Positive Filtering

Create a text file with context about your codebase to reduce false positives:

```text
- Our application uses parameterized queries exclusively via sqlx
- The exec() calls in scripts/build.py are build-time only, not user-facing
- HTML templates use auto-escaping via the template engine
```

Reference it in your workflow:
```yaml
- uses: cosmin/barry@v1
  with:
    google-api-key: ${{ secrets.GOOGLE_API_KEY }}
    github-token: ${{ secrets.GITHUB_TOKEN }}
    false-positive-filtering-instructions: .github/false-positive-rules.txt
```

See [examples/custom-gosec-false-positive-filtering.txt][gosec-fp-ex] for a
full example targeting the [securego/gosec][gosec] project.

[gosec-fp-ex]: examples/custom-gosec-false-positive-filtering.txt
[gosec]: https://github.com/securego/gosec

## GitHub Security Center Integration

Barry can produce [SARIF](https://sarifweb.azurewebsites.net/) (Static Analysis
Results Interchange Format) output, which integrates directly with **GitHub Code
Scanning** and the **Security** tab.

Set `output-format: sarif` to switch from the default JSON output to SARIF.

### Setup

```yaml
name: Security Review
on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  contents: read
  pull-requests: write
  security-events: write   # Required for uploading SARIF

jobs:
  security-review:
    runs-on: ubuntu-latest
    environment: security-review
    steps:
      - uses: actions/checkout@v4

      - uses: cosmin/barry@v1
        id: barry
        with:
          google-api-key: ${{ secrets.GOOGLE_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
          output-format: sarif

      - name: Upload SARIF to GitHub Security
        if: always() && steps.barry.outputs.results-file != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.barry.outputs.results-file }}
```

Once configured, findings appear in the repository's **Security → Code scanning
alerts** tab and in pull request annotations.

## Development

### Prerequisites

- Go 1.26+
- A Google API key with Gemini access

### Build

```bash
go build ./...
```

### Test

```bash
go test ./...
```

### Lint

```bash
golangci-lint run ./...
```

### Running Locally

You can run Barry on your local machine against any open PR on GitHub.

**Requirements:**
- Go 1.26+ installed
- A [Google API key](https://aistudio.google.com/apikey) with Gemini access
- A [GitHub personal access token](https://github.com/settings/tokens) with
  `repo` scope (for private repos) or `public_repo` (for public repos)
- An existing pull request URL (e.g., `https://github.com/owner/repo/pull/123`)

**1. Build the binary:**

```bash
go build -o barry ./main.go
```

**2. Create the event payload for your PR:**

Create `event.json` with the PR number and head commit SHA in the format Barry
expects:

```json
{
  "pull_request": {
    "number": 123,
    "head": {
      "sha": "abc123def456"
    }
  }
}
```

Generate it directly with the GitHub CLI and `jq`:

```bash
gh pr view 123 --repo owner/repo --json number,headRefOid \
  | jq '{pull_request: {number: .number, head: {sha: .headRefOid}}}' \
  > event.json
```

**3. Run:**

```bash
GOOGLE_API_KEY="your-gemini-api-key" \
GITHUB_TOKEN="ghp_your-token" \
GITHUB_REPOSITORY="owner/repo" \
GITHUB_EVENT_PATH="./event.json" \
./barry
```

**Optional environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `INPUT_GEMINI-MODEL` | Gemini model for scanning | `gemini-3-flash-preview` |
| `INPUT_VALIDATOR-MODEL` | Gemini model for validation | `gemini-3-flash-preview` |
| `INPUT_AUTOFIX-MODEL` | Gemini model for generating autofixes | `gemini-3-flash-preview` |
| `INPUT_COMMENT-PR` | Post findings as PR review comments | `true` |
| `INPUT_ENABLE-LLM-FILTERING` | Use a second LLM pass to validate findings | `true` |
| `INPUT_ENABLE-AUTOFIX` | Use an LLM pass to generate autofixes | `true` |
| `INPUT_EXCLUDE-DIRECTORIES` | Comma-separated dirs to skip | `""` |
| `INPUT_TIMEOUT` | Timeout in minutes | `20` |
| `INPUT_OUTPUT-FORMAT` | `json` or `sarif` | `json` |
| `INPUT_OUTPUT-DIR` | Directory to write the results file | `$GITHUB_WORKSPACE` |
| `INPUT_EXCEPTIONS-FILE` | Path to a JSON exceptions file | `""` |
| `INPUT_FALSE-POSITIVE-FILTERING-INSTRUCTIONS` | Path to custom filtering instructions | `""` |
| `INPUT_CUSTOM-SECURITY-SCAN-INSTRUCTIONS` | Path to custom scan instructions | `""` |

**Example — scan PR #42 on a public repo without PR comments:**

```bash
GOOGLE_API_KEY="your-gemini-api-key" \
GITHUB_TOKEN="ghp_your-token" \
GITHUB_REPOSITORY="octocat/hello-world" \
GITHUB_EVENT_PATH="./event.json" \
INPUT_COMMENT-PR="false" \
./barry
```

Results are printed to stdout (JSON) and written to a temp file. Set
`INPUT_OUTPUT-FORMAT=sarif` for SARIF output.

## License

Apache 2.0

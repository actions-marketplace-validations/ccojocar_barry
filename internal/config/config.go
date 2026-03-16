package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all action inputs and environment settings.
type Config struct {
	// Required
	GoogleAPIKey string
	GitHubToken  string

	// Repository context (parsed from GITHUB_REPOSITORY and event payload)
	Owner    string
	Repo     string
	PRNumber int
	HeadSHA  string

	// Models
	ScannerModel   string
	ValidatorModel string
	AutofixModel   string

	// Feature flags
	CommentPR       bool
	UploadResults   bool
	RunEveryCommit  bool
	EnableLLMFilter bool
	EnableAutofix   bool

	// Directories to exclude from scanning
	ExcludeDirectories []string

	// Timeout for the entire action run
	Timeout time.Duration

	// Output format ("json" or "sarif")
	OutputFormat string

	// Directory for output files (defaults to os.TempDir())
	OutputDir string

	// Custom instruction file contents (loaded at startup)
	CustomFilteringInstructions string
	CustomScanInstructions      string

	// Exceptions loaded from a JSON file (see filter.Exception).
	ExceptionsFile string
}

// Load reads configuration from environment variables and the GitHub event payload.
func Load() (*Config, error) {
	cfg := &Config{
		ScannerModel:    envOrDefault("INPUT_GEMINI-MODEL", "gemini-3-flash-preview"),
		ValidatorModel:  envOrDefault("INPUT_VALIDATOR-MODEL", "gemini-3-flash-preview"),
		AutofixModel:    envOrDefault("INPUT_AUTOFIX-MODEL", "gemini-3-flash-preview"),
		CommentPR:       envBool("INPUT_COMMENT-PR", true),
		UploadResults:   envBool("INPUT_UPLOAD-RESULTS", true),
		RunEveryCommit:  envBool("INPUT_RUN-EVERY-COMMIT", false),
		EnableLLMFilter: envBool("INPUT_ENABLE-LLM-FILTERING", true),
		EnableAutofix:   envBool("INPUT_ENABLE-AUTOFIX", true),
	}

	// Required secrets / tokens
	var err error
	cfg.GoogleAPIKey, err = requireEnv("google API key is required (INPUT_GOOGLE-API-KEY or GOOGLE_API_KEY)", "INPUT_GOOGLE-API-KEY", "GOOGLE_API_KEY")
	if err != nil {
		return nil, err
	}

	cfg.GitHubToken, err = requireEnv("github token is required (INPUT_GITHUB-TOKEN or GITHUB_TOKEN)", "INPUT_GITHUB-TOKEN", "GITHUB_TOKEN")
	if err != nil {
		return nil, err
	}

	// Repository owner/repo
	repoFull := os.Getenv("GITHUB_REPOSITORY")
	if repoFull == "" {
		return nil, errors.New("GITHUB_REPOSITORY is required")
	}
	parts := strings.SplitN(repoFull, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid GITHUB_REPOSITORY format: %s", repoFull)
	}
	cfg.Owner = parts[0]
	cfg.Repo = parts[1]

	// PR number + head SHA from event payload
	if err := cfg.loadEventPayload(); err != nil {
		return nil, fmt.Errorf("loading event payload: %w", err)
	}

	// Timeout
	timeoutMin, _ := strconv.Atoi(envOrDefault("INPUT_TIMEOUT", "20"))
	cfg.Timeout = time.Duration(timeoutMin) * time.Minute

	// Exclude directories
	if dirs := os.Getenv("INPUT_EXCLUDE-DIRECTORIES"); dirs != "" {
		for _, d := range strings.Split(dirs, ",") {
			if trimmed := strings.TrimSpace(d); trimmed != "" {
				cfg.ExcludeDirectories = append(cfg.ExcludeDirectories, trimmed)
			}
		}
	}

	// Output format
	cfg.OutputFormat = strings.ToLower(envOrDefault("INPUT_OUTPUT-FORMAT", "json"))
	if cfg.OutputFormat != "json" && cfg.OutputFormat != "sarif" {
		return nil, fmt.Errorf("invalid output-format %q: must be \"json\" or \"sarif\"", cfg.OutputFormat)
	}

	// Custom instruction files
	cfg.CustomFilteringInstructions, err = loadOptionalFile("INPUT_FALSE-POSITIVE-FILTERING-INSTRUCTIONS")
	if err != nil {
		return nil, fmt.Errorf("reading custom filtering instructions: %w", err)
	}

	cfg.CustomScanInstructions, err = loadOptionalFile("INPUT_CUSTOM-SECURITY-SCAN-INSTRUCTIONS")
	if err != nil {
		return nil, fmt.Errorf("reading custom scan instructions: %w", err)
	}

	cfg.ExceptionsFile = os.Getenv("INPUT_EXCEPTIONS-FILE")

	// Default output directory to $GITHUB_WORKSPACE so results are accessible
	// from the host runner (Docker containers write to /tmp by default, which
	// is not visible outside the container).
	cfg.OutputDir = envOrDefault("INPUT_OUTPUT-DIR", os.Getenv("GITHUB_WORKSPACE"))

	return cfg, nil
}

// loadEventPayload reads GITHUB_EVENT_PATH JSON to extract PR number and head SHA.
func (c *Config) loadEventPayload() error {
	eventPath := os.Getenv("GITHUB_EVENT_PATH")
	if eventPath == "" {
		return errors.New("GITHUB_EVENT_PATH is required")
	}

	data, err := os.ReadFile(eventPath)
	if err != nil {
		return fmt.Errorf("reading event file: %w", err)
	}

	var event struct {
		PullRequest struct {
			Number int `json:"number"`
			Head   struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_request"`
	}

	if err := json.Unmarshal(data, &event); err != nil {
		return fmt.Errorf("parsing event JSON: %w", err)
	}

	if event.PullRequest.Number == 0 {
		return errors.New("no pull_request.number in event payload")
	}

	c.PRNumber = event.PullRequest.Number
	c.HeadSHA = event.PullRequest.Head.SHA
	return nil
}

// --- helpers ---

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// requireEnv returns the first non-empty value from the given env var keys,
// or an error with errMsg if none are set.
func requireEnv(errMsg string, keys ...string) (string, error) {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v, nil
		}
	}
	return "", errors.New(errMsg)
}

// loadOptionalFile reads the file path from the given env var key and returns
// its contents. Returns empty string if the env var is not set.
func loadOptionalFile(envKey string) (string, error) {
	path := os.Getenv(envKey)
	if path == "" {
		return "", nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

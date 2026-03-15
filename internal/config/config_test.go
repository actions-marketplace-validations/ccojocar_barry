package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setRequiredEnv sets the minimum env vars needed for Load() to succeed.
// Returns the path to the temp event file so callers can customise it.
func setRequiredEnv(t *testing.T) string {
	t.Helper()
	t.Setenv("INPUT_GOOGLE-API-KEY", "test-api-key")
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")

	eventFile := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(eventFile, []byte(`{"pull_request":{"number":42,"head":{"sha":"abc123"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_EVENT_PATH", eventFile)
	return eventFile
}

func TestLoad_HappyPath(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("INPUT_GEMINI-MODEL", "gemini-2.0-flash")
	t.Setenv("INPUT_VALIDATOR-MODEL", "gemini-2.0-flash")
	t.Setenv("INPUT_AUTOFIX-MODEL", "gemini-2.0-flash")
	t.Setenv("INPUT_COMMENT-PR", "false")
	t.Setenv("INPUT_UPLOAD-RESULTS", "false")
	t.Setenv("INPUT_RUN-EVERY-COMMIT", "true")
	t.Setenv("INPUT_ENABLE-LLM-FILTERING", "false")
	t.Setenv("INPUT_ENABLE-AUTOFIX", "false")
	t.Setenv("INPUT_TIMEOUT", "5")
	t.Setenv("INPUT_OUTPUT-FORMAT", "sarif")
	t.Setenv("INPUT_EXCLUDE-DIRECTORIES", "vendor, node_modules, .git")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.Owner != "owner" || cfg.Repo != "repo" {
		t.Errorf("Owner/Repo = %s/%s, want owner/repo", cfg.Owner, cfg.Repo)
	}
	if cfg.PRNumber != 42 {
		t.Errorf("PRNumber = %d, want 42", cfg.PRNumber)
	}
	if cfg.HeadSHA != "abc123" {
		t.Errorf("HeadSHA = %q, want %q", cfg.HeadSHA, "abc123")
	}
	if cfg.ScannerModel != "gemini-2.0-flash" {
		t.Errorf("ScannerModel = %q, want gemini-2.0-flash", cfg.ScannerModel)
	}
	if cfg.ValidatorModel != "gemini-2.0-flash" {
		t.Errorf("ValidatorModel = %q, want gemini-2.0-flash", cfg.ValidatorModel)
	}
	if cfg.AutofixModel != "gemini-2.0-flash" {
		t.Errorf("AutofixModel = %q, want gemini-2.0-flash", cfg.AutofixModel)
	}
	if cfg.CommentPR {
		t.Error("CommentPR should be false")
	}
	if cfg.UploadResults {
		t.Error("UploadResults should be false")
	}
	if !cfg.RunEveryCommit {
		t.Error("RunEveryCommit should be true")
	}
	if cfg.EnableLLMFilter {
		t.Error("EnableLLMFilter should be false")
	}
	if cfg.EnableAutofix {
		t.Error("EnableAutofix should be false")
	}
	if cfg.Timeout != 5*time.Minute {
		t.Errorf("Timeout = %v, want 5m", cfg.Timeout)
	}
	if cfg.OutputFormat != "sarif" {
		t.Errorf("OutputFormat = %q, want sarif", cfg.OutputFormat)
	}
	if len(cfg.ExcludeDirectories) != 3 {
		t.Fatalf("ExcludeDirectories len = %d, want 3", len(cfg.ExcludeDirectories))
	}
	for _, d := range cfg.ExcludeDirectories {
		if d != strings.TrimSpace(d) {
			t.Errorf("ExcludeDirectories entry %q not trimmed", d)
		}
	}
}

func TestLoad_Defaults(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.ScannerModel != "gemini-3.1-pro-preview" {
		t.Errorf("default ScannerModel = %q, want gemini-3.1-pro-preview", cfg.ScannerModel)
	}
	if cfg.ValidatorModel != "gemini-3.1-flash-preview" {
		t.Errorf("default ValidatorModel = %q, want gemini-3.1-flash-preview", cfg.ValidatorModel)
	}
	if cfg.AutofixModel != "gemini-3.1-pro-preview" {
		t.Errorf("default AutofixModel = %q, want gemini-3.1-pro-preview", cfg.AutofixModel)
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("default OutputFormat = %q, want json", cfg.OutputFormat)
	}
	if !cfg.CommentPR {
		t.Error("default CommentPR should be true")
	}
	if !cfg.EnableLLMFilter {
		t.Error("default EnableLLMFilter should be true")
	}
	if !cfg.EnableAutofix {
		t.Error("default EnableAutofix should be true")
	}
	if cfg.Timeout != 20*time.Minute {
		t.Errorf("default Timeout = %v, want 20m", cfg.Timeout)
	}
}

func TestLoad_MissingGoogleAPIKey(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("INPUT_GOOGLE-API-KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "google API key is required") {
		t.Errorf("Load() error = %v, want 'google API key is required'", err)
	}
}

func TestLoad_MissingGitHubToken(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("INPUT_GITHUB-TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "github token is required") {
		t.Errorf("Load() error = %v, want 'github token is required'", err)
	}
}

func TestLoad_MissingGitHubRepository(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("GITHUB_REPOSITORY", "")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "GITHUB_REPOSITORY is required") {
		t.Errorf("Load() error = %v, want 'GITHUB_REPOSITORY is required'", err)
	}
}

func TestLoad_InvalidGitHubRepository(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("GITHUB_REPOSITORY", "noslash")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "invalid GITHUB_REPOSITORY format") {
		t.Errorf("Load() error = %v, want 'invalid GITHUB_REPOSITORY format'", err)
	}
}

func TestLoad_InvalidOutputFormat(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("INPUT_OUTPUT-FORMAT", "xml")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "invalid output-format") {
		t.Errorf("Load() error = %v, want 'invalid output-format'", err)
	}
}

func TestLoad_CustomFilteringInstructions(t *testing.T) {
	setRequiredEnv(t)
	tmpFile := filepath.Join(t.TempDir(), "filter.txt")
	if err := os.WriteFile(tmpFile, []byte("custom filtering content"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INPUT_FALSE-POSITIVE-FILTERING-INSTRUCTIONS", tmpFile)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.CustomFilteringInstructions != "custom filtering content" {
		t.Errorf("CustomFilteringInstructions = %q, want 'custom filtering content'", cfg.CustomFilteringInstructions)
	}
}

func TestLoad_CustomScanInstructions(t *testing.T) {
	setRequiredEnv(t)
	tmpFile := filepath.Join(t.TempDir(), "scan.txt")
	if err := os.WriteFile(tmpFile, []byte("custom scan content"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INPUT_CUSTOM-SECURITY-SCAN-INSTRUCTIONS", tmpFile)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.CustomScanInstructions != "custom scan content" {
		t.Errorf("CustomScanInstructions = %q, want 'custom scan content'", cfg.CustomScanInstructions)
	}
}

func TestLoad_CustomInstructionFileNotFound(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("INPUT_FALSE-POSITIVE-FILTERING-INSTRUCTIONS", "/nonexistent/path.txt")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "reading custom filtering instructions") {
		t.Errorf("Load() error = %v, want 'reading custom filtering instructions'", err)
	}
}

func TestLoadEventPayload_MissingEventPath(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("GITHUB_EVENT_PATH", "")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "GITHUB_EVENT_PATH is required") {
		t.Errorf("Load() error = %v, want 'GITHUB_EVENT_PATH is required'", err)
	}
}

func TestLoadEventPayload_InvalidJSON(t *testing.T) {
	setRequiredEnv(t)
	badFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badFile, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_EVENT_PATH", badFile)

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "parsing event JSON") {
		t.Errorf("Load() error = %v, want 'parsing event JSON'", err)
	}
}

func TestLoadEventPayload_MissingPRNumber(t *testing.T) {
	setRequiredEnv(t)
	f := filepath.Join(t.TempDir(), "noPR.json")
	if err := os.WriteFile(f, []byte(`{"pull_request":{"number":0}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_EVENT_PATH", f)

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "no pull_request.number") {
		t.Errorf("Load() error = %v, want 'no pull_request.number'", err)
	}
}

func TestEnvOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		setVal   string
		fallback string
		want     string
	}{
		{name: "returns env value", key: "TEST_ENV_OR_DEFAULT_1", setVal: "hello", fallback: "world", want: "hello"},
		{name: "returns fallback", key: "TEST_ENV_OR_DEFAULT_2", setVal: "", fallback: "fallback", want: "fallback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setVal != "" {
				t.Setenv(tt.key, tt.setVal)
			}
			got := envOrDefault(tt.key, tt.fallback)
			if got != tt.want {
				t.Errorf("envOrDefault(%q, %q) = %q, want %q", tt.key, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestEnvBool(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		setVal   string
		fallback bool
		want     bool
	}{
		{name: "true string", key: "TEST_ENVBOOL_1", setVal: "true", fallback: false, want: true},
		{name: "false string", key: "TEST_ENVBOOL_2", setVal: "false", fallback: true, want: false},
		{name: "empty uses fallback true", key: "TEST_ENVBOOL_3", setVal: "", fallback: true, want: true},
		{name: "empty uses fallback false", key: "TEST_ENVBOOL_4", setVal: "", fallback: false, want: false},
		{name: "invalid uses fallback", key: "TEST_ENVBOOL_5", setVal: "notbool", fallback: true, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setVal != "" {
				t.Setenv(tt.key, tt.setVal)
			}
			got := envBool(tt.key, tt.fallback)
			if got != tt.want {
				t.Errorf("envBool(%q, %v) = %v, want %v", tt.key, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestRequireEnv(t *testing.T) {
	t.Run("returns first set env var", func(t *testing.T) {
		t.Setenv("TEST_REQ_A", "")
		t.Setenv("TEST_REQ_B", "hello")
		got, err := requireEnv("missing", "TEST_REQ_A", "TEST_REQ_B")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "hello" {
			t.Errorf("got %q, want %q", got, "hello")
		}
	})
	t.Run("returns error when all empty", func(t *testing.T) {
		t.Setenv("TEST_REQ_C", "")
		t.Setenv("TEST_REQ_D", "")
		_, err := requireEnv("all missing", "TEST_REQ_C", "TEST_REQ_D")
		if err == nil {
			t.Fatal("expected error")
		}
		if err.Error() != "all missing" {
			t.Errorf("error = %q, want %q", err.Error(), "all missing")
		}
	})
}

func TestLoad_CustomScanInstructionFileNotFound(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("INPUT_CUSTOM-SECURITY-SCAN-INSTRUCTIONS", "/nonexistent/path.txt")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "reading custom scan instructions") {
		t.Errorf("Load() error = %v, want 'reading custom scan instructions'", err)
	}
}

func TestLoadEventPayload_FileReadError(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("GITHUB_EVENT_PATH", "/nonexistent/dir/event.json")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "reading event file") {
		t.Errorf("Load() error = %v, want 'reading event file'", err)
	}
}

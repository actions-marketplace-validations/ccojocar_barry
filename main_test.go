package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmin/barry/internal/agents"
	"github.com/cosmin/barry/internal/config"
	"github.com/cosmin/barry/internal/findings"
	gh "github.com/cosmin/barry/internal/github"
	ghlib "github.com/google/go-github/v68/github"
)

func TestWriteOutput_NoEnvVar(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", "")
	writeOutput("key", "val")
}

func TestWriteOutput_WritesToFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "output.txt")
	t.Setenv("GITHUB_OUTPUT", f)
	writeOutput("findings-count", "3")
	writeOutput("results-file", "/tmp/results.json")
	data, err := os.ReadFile(f)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "findings-count=3") {
		t.Errorf("missing findings-count, got: %s", content)
	}
	if !strings.Contains(content, "results-file=/tmp/results.json") {
		t.Errorf("missing results-file, got: %s", content)
	}
}

func TestWriteOutput_InvalidPath(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", "/nonexistent/dir/output")
	writeOutput("key", "val")
}

func TestWriteSARIF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.sarif")
	output := &findings.ScanOutput{
		Findings: []findings.Finding{
			{File: "a.go", Line: 10, Severity: "HIGH", Category: "xss", Description: "XSS"},
		},
	}
	if err := writeSARIF(path, output); err != nil {
		t.Fatalf("writeSARIF: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading SARIF: %v", err)
	}
	if !strings.Contains(string(data), "BARRY") {
		t.Error("SARIF output should contain BARRY rules")
	}
}

func TestWriteSARIF_InvalidPath(t *testing.T) {
	err := writeSARIF("/nonexistent/dir/report.sarif", &findings.ScanOutput{})
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestOutputResults_DefaultOutputDir(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	cfg := &config.Config{OutputFormat: "json"} // OutputDir empty → falls back to os.TempDir()
	prData := &gh.PRData{}
	result := &findings.PipelineResult{Findings: findings.ScanOutput{}}
	err := outputResults(context.Background(), cfg, nil, prData, result, slog.Default())
	if err != nil {
		t.Fatalf("outputResults: %v", err)
	}
	// Verify the file was written to the temp directory.
	resultsFile := filepath.Join(os.TempDir(), "barry-results.json")
	if _, err := os.Stat(resultsFile); err != nil {
		t.Fatalf("results file not found in default dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(resultsFile) })
}

func TestOutputResults_JSONFormat_NoFindings(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	outDir := t.TempDir()
	cfg := &config.Config{OutputFormat: "json", OutputDir: outDir}
	prData := &gh.PRData{}
	result := &findings.PipelineResult{Findings: findings.ScanOutput{}}
	err := outputResults(context.Background(), cfg, nil, prData, result, slog.Default())
	if err != nil {
		t.Fatalf("outputResults: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "barry-results.json"))
	if err != nil {
		t.Fatalf("reading results: %v", err)
	}
	var out findings.ScanOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshaling results: %v", err)
	}
}

func TestOutputResults_SARIFFormat(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	outDir := t.TempDir()
	cfg := &config.Config{OutputFormat: "sarif", OutputDir: outDir}
	prData := &gh.PRData{}
	result := &findings.PipelineResult{
		Findings: findings.ScanOutput{
			Findings: []findings.Finding{
				{File: "a.go", Line: 1, Severity: "MEDIUM", Category: "test"},
			},
		},
	}
	err := outputResults(context.Background(), cfg, nil, prData, result, slog.Default())
	if err != nil {
		t.Fatalf("outputResults: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "barry-results.sarif"))
	if err != nil {
		t.Fatalf("reading SARIF: %v", err)
	}
	if !strings.Contains(string(data), "BARRY") {
		t.Error("SARIF output should contain BARRY")
	}
}

func TestOutputResults_HighSeverityReturnsError(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	cfg := &config.Config{OutputFormat: "json", OutputDir: t.TempDir()}
	prData := &gh.PRData{}
	result := &findings.PipelineResult{
		Findings: findings.ScanOutput{
			Findings: []findings.Finding{
				{File: "a.go", Line: 1, Severity: "HIGH", Category: "sqli"},
			},
		},
	}
	err := outputResults(context.Background(), cfg, nil, prData, result, slog.Default())
	if !errors.Is(err, errHighSeverity) {
		t.Errorf("expected errHighSeverity, got: %v", err)
	}
}

func TestOutputResults_MediumSeverityNoError(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	cfg := &config.Config{OutputFormat: "json", OutputDir: t.TempDir()}
	prData := &gh.PRData{}
	result := &findings.PipelineResult{
		Findings: findings.ScanOutput{
			Findings: []findings.Finding{
				{File: "a.go", Line: 1, Severity: "MEDIUM", Category: "xss"},
			},
		},
	}
	err := outputResults(context.Background(), cfg, nil, prData, result, slog.Default())
	if err != nil {
		t.Fatalf("expected no error for MEDIUM severity, got: %v", err)
	}
}

func TestOutputResults_WithCommentPR(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := http.NewServeMux()
	var reviewCalled bool
	mux.HandleFunc("/repos/owner/repo/pulls/1/reviews", func(w http.ResponseWriter, _ *http.Request) {
		reviewCalled = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&ghlib.PullRequestReview{ID: ghlib.Ptr(int64(1))})
	})
	client := setupGHServer(t, mux)
	cfg := &config.Config{
		OutputFormat: "json",
		OutputDir:    t.TempDir(),
		CommentPR:    true,
		PRNumber:     1,
		HeadSHA:      "abc123",
	}
	prData := &gh.PRData{HeadSHA: "def456"}
	result := &findings.PipelineResult{
		Findings: findings.ScanOutput{
			Findings: []findings.Finding{
				{File: "a.go", Line: 5, Severity: "MEDIUM", Category: "xss", Description: "XSS vuln"},
			},
		},
	}
	err := outputResults(context.Background(), cfg, client, prData, result, slog.Default())
	if err != nil {
		t.Fatalf("outputResults: %v", err)
	}
	if !reviewCalled {
		t.Error("expected PR review to be posted")
	}
}

func TestOutputResults_CommentPR_UsesHeadSHAFallback(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1/reviews", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&ghlib.PullRequestReview{ID: ghlib.Ptr(int64(1))})
	})
	client := setupGHServer(t, mux)
	cfg := &config.Config{
		OutputFormat: "json",
		OutputDir:    t.TempDir(),
		CommentPR:    true,
		PRNumber:     1,
		HeadSHA:      "",
	}
	prData := &gh.PRData{HeadSHA: "fallback-sha"}
	result := &findings.PipelineResult{
		Findings: findings.ScanOutput{
			Findings: []findings.Finding{
				{File: "a.go", Line: 5, Severity: "MEDIUM", Category: "xss", Description: "XSS vuln"},
			},
		},
	}
	err := outputResults(context.Background(), cfg, client, prData, result, slog.Default())
	if err != nil {
		t.Fatalf("outputResults: %v", err)
	}
}

// --- runCore tests ---

// setupGHServer creates a httptest server and a gh.Client for testing runCore.
// The mux handlers should be set up before calling this.
func setupGHServer(t *testing.T, mux *http.ServeMux) *gh.Client {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	httpClient := srv.Client()
	ghClient := ghlib.NewClient(httpClient).WithAuthToken("test-token")
	ghClient.BaseURL, _ = ghClient.BaseURL.Parse(srv.URL + "/")
	return gh.NewClientWithGH(ghClient, "owner", "repo")
}

// fakePipeline returns a pipelineFunc that returns the given result/error.
func fakePipeline(result *findings.PipelineResult, err error) pipelineFunc {
	return func(_ context.Context, _ agents.PipelineConfig) (*findings.PipelineResult, error) {
		return result, err
	}
}

// prJSON returns a JSON-encodable PR object for httptest handlers.
func prJSON() *ghlib.PullRequest {
	return &ghlib.PullRequest{
		Number:       ghlib.Ptr(1),
		Title:        ghlib.Ptr("test PR"),
		Body:         ghlib.Ptr("body"),
		User:         &ghlib.User{Login: ghlib.Ptr("dev")},
		Head:         &ghlib.PullRequestBranch{SHA: ghlib.Ptr("abc"), Repo: &ghlib.Repository{FullName: ghlib.Ptr("owner/repo")}},
		Additions:    ghlib.Ptr(10),
		Deletions:    ghlib.Ptr(5),
		ChangedFiles: ghlib.Ptr(1),
	}
}

func baseMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept"), "diff") {
			_, _ = w.Write([]byte("diff --git a/src/main.go b/src/main.go\n+line\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(prJSON())
	})
	mux.HandleFunc("/repos/owner/repo/pulls/1/files", func(w http.ResponseWriter, _ *http.Request) {
		files := []*ghlib.CommitFile{
			{Filename: ghlib.Ptr("src/main.go"), Status: ghlib.Ptr("modified"), Additions: ghlib.Ptr(5), Deletions: ghlib.Ptr(2)},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(files)
	})
	return mux
}

func baseCfg(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		PRNumber:     1,
		OutputFormat: "json",
		OutputDir:    t.TempDir(),
		Timeout:      30 * time.Second,
	}
}

func TestRunCore_HappyPath_NoFindings(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := baseMux(t)
	client := setupGHServer(t, mux)

	result := &findings.PipelineResult{Findings: findings.ScanOutput{}}
	err := runCore(context.Background(), baseCfg(t), client, fakePipeline(result, nil), slog.Default())
	if err != nil {
		t.Fatalf("runCore: %v", err)
	}
}

func TestRunCore_HappyPath_WithFindings(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := baseMux(t)
	client := setupGHServer(t, mux)

	result := &findings.PipelineResult{
		Findings: findings.ScanOutput{
			Findings: []findings.Finding{
				{File: "src/main.go", Line: 10, Severity: "MEDIUM", Category: "xss", Description: "XSS"},
			},
		},
	}
	err := runCore(context.Background(), baseCfg(t), client, fakePipeline(result, nil), slog.Default())
	if err != nil {
		t.Fatalf("runCore: %v", err)
	}
}

func TestRunCore_HighSeverity(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := baseMux(t)
	client := setupGHServer(t, mux)

	result := &findings.PipelineResult{
		Findings: findings.ScanOutput{
			Findings: []findings.Finding{
				{File: "src/main.go", Line: 10, Severity: "HIGH", Category: "sqli"},
			},
		},
	}
	err := runCore(context.Background(), baseCfg(t), client, fakePipeline(result, nil), slog.Default())
	if !errors.Is(err, errHighSeverity) {
		t.Errorf("expected errHighSeverity, got: %v", err)
	}
}

func TestRunCore_GetPRDataError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	client := setupGHServer(t, mux)

	err := runCore(context.Background(), baseCfg(t), client, fakePipeline(nil, nil), slog.Default())
	if err == nil || !strings.Contains(err.Error(), "fetching PR data") {
		t.Fatalf("expected PR data error, got: %v", err)
	}
}

func TestRunCore_AllFilesFiltered(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("GITHUB_OUTPUT", filepath.Join(tmpDir, "output.txt"))

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept"), "diff") {
			_, _ = w.Write([]byte("diff"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(prJSON())
	})
	mux.HandleFunc("/repos/owner/repo/pulls/1/files", func(w http.ResponseWriter, _ *http.Request) {
		// Return only a .lock file that should be filtered out
		files := []*ghlib.CommitFile{
			{Filename: ghlib.Ptr("vendor/dep.go"), Status: ghlib.Ptr("modified"), Additions: ghlib.Ptr(1), Deletions: ghlib.Ptr(0)},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(files)
	})
	client := setupGHServer(t, mux)

	cfg := baseCfg(t)
	cfg.ExcludeDirectories = []string{"vendor"}

	pipelineCalled := false
	fakePF := func(_ context.Context, _ agents.PipelineConfig) (*findings.PipelineResult, error) {
		pipelineCalled = true
		return nil, nil
	}

	err := runCore(context.Background(), cfg, client, fakePF, slog.Default())
	if err != nil {
		t.Fatalf("runCore: %v", err)
	}
	if pipelineCalled {
		t.Error("pipeline should not be called when all files are filtered")
	}
}

func TestRunCore_DiffFetchError_ContinuesWithoutDiff(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept"), "diff") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(prJSON())
	})
	mux.HandleFunc("/repos/owner/repo/pulls/1/files", func(w http.ResponseWriter, _ *http.Request) {
		files := []*ghlib.CommitFile{
			{Filename: ghlib.Ptr("src/main.go"), Status: ghlib.Ptr("modified"), Additions: ghlib.Ptr(5), Deletions: ghlib.Ptr(2)},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(files)
	})
	client := setupGHServer(t, mux)

	result := &findings.PipelineResult{Findings: findings.ScanOutput{}}
	err := runCore(context.Background(), baseCfg(t), client, fakePipeline(result, nil), slog.Default())
	if err != nil {
		t.Fatalf("runCore: %v", err)
	}
}

func TestRunCore_PipelineError_RetrySucceeds(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := baseMux(t)
	client := setupGHServer(t, mux)

	callCount := 0
	retryPipeline := func(_ context.Context, _ agents.PipelineConfig) (*findings.PipelineResult, error) {
		callCount++
		if callCount == 1 {
			return nil, fmt.Errorf("first call fails")
		}
		return &findings.PipelineResult{Findings: findings.ScanOutput{}}, nil
	}

	err := runCore(context.Background(), baseCfg(t), client, retryPipeline, slog.Default())
	if err != nil {
		t.Fatalf("runCore: %v", err)
	}
	if callCount != 2 {
		t.Errorf("pipeline called %d times, want 2", callCount)
	}
}

func TestRunCore_PipelineError_RetryAlsoFails(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := baseMux(t)
	client := setupGHServer(t, mux)

	alwaysFail := func(_ context.Context, _ agents.PipelineConfig) (*findings.PipelineResult, error) {
		return nil, fmt.Errorf("pipeline error")
	}

	err := runCore(context.Background(), baseCfg(t), client, alwaysFail, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "pipeline execution (retry)") {
		t.Fatalf("expected retry error, got: %v", err)
	}
}

func TestRunCore_SARIFOutput(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := baseMux(t)
	client := setupGHServer(t, mux)

	cfg := baseCfg(t)
	cfg.OutputFormat = "sarif"
	result := &findings.PipelineResult{
		Findings: findings.ScanOutput{
			Findings: []findings.Finding{
				{File: "src/main.go", Line: 1, Severity: "MEDIUM", Category: "xss", Description: "XSS"},
			},
		},
	}
	err := runCore(context.Background(), cfg, client, fakePipeline(result, nil), slog.Default())
	if err != nil {
		t.Fatalf("runCore: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(cfg.OutputDir, "barry-results.sarif"))
	if err != nil {
		t.Fatalf("reading SARIF: %v", err)
	}
	if !strings.Contains(string(data), "BARRY") {
		t.Error("SARIF output should contain BARRY rules")
	}
}

func TestRunCore_WithCommentPR(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := baseMux(t)
	var reviewPosted bool
	mux.HandleFunc("/repos/owner/repo/pulls/1/reviews", func(w http.ResponseWriter, _ *http.Request) {
		reviewPosted = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&ghlib.PullRequestReview{ID: ghlib.Ptr(int64(1))})
	})
	client := setupGHServer(t, mux)

	cfg := baseCfg(t)
	cfg.CommentPR = true
	cfg.HeadSHA = "sha123"
	result := &findings.PipelineResult{
		Findings: findings.ScanOutput{
			Findings: []findings.Finding{
				{File: "src/main.go", Line: 5, Severity: "MEDIUM", Category: "xss", Description: "XSS vuln"},
			},
		},
	}
	err := runCore(context.Background(), cfg, client, fakePipeline(result, nil), slog.Default())
	if err != nil {
		t.Fatalf("runCore: %v", err)
	}
	if !reviewPosted {
		t.Error("expected PR review to be posted")
	}
}

func TestOutputResults_CommentPR_PostError(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1/reviews", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/repos/owner/repo/pulls/1/comments", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	client := setupGHServer(t, mux)

	cfg := &config.Config{
		OutputFormat: "json",
		OutputDir:    t.TempDir(),
		CommentPR:    true,
		PRNumber:     1,
		HeadSHA:      "sha",
	}
	prData := &gh.PRData{HeadSHA: "sha"}
	result := &findings.PipelineResult{
		Findings: findings.ScanOutput{
			Findings: []findings.Finding{
				{File: "a.go", Line: 5, Severity: "MEDIUM", Category: "xss", Description: "XSS vuln"},
			},
		},
	}
	// Should not return error even when review post fails.
	err := outputResults(context.Background(), cfg, client, prData, result, slog.Default())
	if err != nil {
		t.Fatalf("outputResults should not fail on PR comment error: %v", err)
	}
}

func TestOutputResults_SARIFWriteError(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	cfg := &config.Config{OutputFormat: "sarif", OutputDir: "/nonexistent/dir"}
	prData := &gh.PRData{}
	result := &findings.PipelineResult{Findings: findings.ScanOutput{}}

	// Use a nonexistent directory to trigger write error.
	err := outputResults(context.Background(), cfg, nil, prData, result, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "writing SARIF results") {
		t.Fatalf("expected SARIF write error, got: %v", err)
	}
}

func TestOutputResults_JSONWriteError(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	cfg := &config.Config{OutputFormat: "json", OutputDir: "/nonexistent/dir"}
	prData := &gh.PRData{}
	result := &findings.PipelineResult{Findings: findings.ScanOutput{}}

	// Use a nonexistent directory to trigger write error.
	err := outputResults(context.Background(), cfg, nil, prData, result, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "writing JSON results") {
		t.Fatalf("expected JSON write error, got: %v", err)
	}
}

func TestRunCore_NoFilesToScan(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept"), "diff") {
			_, _ = w.Write([]byte("diff"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(prJSON())
	})
	mux.HandleFunc("/repos/owner/repo/pulls/1/files", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]*ghlib.CommitFile{})
	})
	client := setupGHServer(t, mux)

	err := runCore(context.Background(), baseCfg(t), client, fakePipeline(nil, nil), slog.Default())
	if err != nil {
		t.Fatalf("runCore: %v", err)
	}
}

func TestRunCore_DiffFetchError(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept"), "diff") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(prJSON())
	})
	mux.HandleFunc("/repos/owner/repo/pulls/1/files", func(w http.ResponseWriter, _ *http.Request) {
		files := []*ghlib.CommitFile{
			{Filename: ghlib.Ptr("src/main.go"), Status: ghlib.Ptr("modified"), Additions: ghlib.Ptr(5), Deletions: ghlib.Ptr(2)},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(files)
	})
	client := setupGHServer(t, mux)

	result := &findings.PipelineResult{Findings: findings.ScanOutput{}}
	err := runCore(context.Background(), baseCfg(t), client, fakePipeline(result, nil), slog.Default())
	if err != nil {
		t.Fatalf("runCore: %v", err)
	}
}

func TestRunCore_PipelineFallback(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := baseMux(t)
	client := setupGHServer(t, mux)

	calls := 0
	pipeline := func(_ context.Context, _ agents.PipelineConfig) (*findings.PipelineResult, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("pipeline failed")
		}
		return &findings.PipelineResult{Findings: findings.ScanOutput{}}, nil
	}

	err := runCore(context.Background(), baseCfg(t), client, pipeline, slog.Default())
	if err != nil {
		t.Fatalf("runCore: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}

func TestRunCore_PipelineFallbackFailure(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := baseMux(t)
	client := setupGHServer(t, mux)

	pipeline := func(_ context.Context, _ agents.PipelineConfig) (*findings.PipelineResult, error) {
		return nil, errors.New("pipeline failed")
	}

	err := runCore(context.Background(), baseCfg(t), client, pipeline, slog.Default())
	if err == nil {
		t.Fatal("expected error from runCore when fallback fails")
	}
}

func TestRunCore_WithExceptions(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := baseMux(t)
	client := setupGHServer(t, mux)

	tempFile := filepath.Join(t.TempDir(), "exceptions.json")
	_ = os.WriteFile(tempFile, []byte(`{"exceptions":[{"category":"test","reason":"just because"}]}`), 0644)

	cfg := baseCfg(t)
	cfg.ExceptionsFile = tempFile

	result := &findings.PipelineResult{Findings: findings.ScanOutput{}}
	err := runCore(context.Background(), cfg, client, fakePipeline(result, nil), slog.Default())
	if err != nil {
		t.Fatalf("runCore: %v", err)
	}
}

func TestRunCore_InvalidExceptionsFile(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", filepath.Join(t.TempDir(), "output.txt"))
	mux := baseMux(t)
	client := setupGHServer(t, mux)

	cfg := baseCfg(t)
	cfg.ExceptionsFile = "/nonexistent/file"

	err := runCore(context.Background(), cfg, client, fakePipeline(nil, nil), slog.Default())
	if err == nil {
		t.Fatal("expected error for invalid exceptions file")
	}
}

func TestRunCore_PRDataError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	client := setupGHServer(t, mux)

	err := runCore(context.Background(), baseCfg(t), client, fakePipeline(nil, nil), slog.Default())
	if err == nil {
		t.Fatal("expected error from runCore when PR data fetch fails")
	}
}

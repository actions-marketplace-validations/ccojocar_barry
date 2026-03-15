package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cosmin/barry/internal/agents"
	"github.com/cosmin/barry/internal/comment"
	"github.com/cosmin/barry/internal/config"
	"github.com/cosmin/barry/internal/filter"
	"github.com/cosmin/barry/internal/findings"
	gh "github.com/cosmin/barry/internal/github"
	"github.com/cosmin/barry/internal/logging"
	"github.com/cosmin/barry/internal/sarif"
)

// errHighSeverity is returned when HIGH severity findings are detected.
var errHighSeverity = errors.New("HIGH severity findings detected")

func main() {
	log := logging.Get()
	if err := run(); err != nil {
		if errors.Is(err, errHighSeverity) {
			log.Info(err.Error())
			os.Exit(1)
		}
		log.Error("Fatal", "error", err)
		os.Exit(1)
	}
}

// pipelineFunc is the signature for running the agent pipeline.
type pipelineFunc func(ctx context.Context, cfg agents.PipelineConfig) (*findings.PipelineResult, error)

func run() error {
	ctx := context.Background()
	log := logging.Get()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	log.Info("Configuration loaded",
		"owner", cfg.Owner,
		"repo", cfg.Repo,
		"pr", cfg.PRNumber,
		"scanner_model", cfg.ScannerModel,
		"llm_filter", cfg.EnableLLMFilter,
	)

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	ghClient := gh.NewClient(cfg.GitHubToken, cfg.Owner, cfg.Repo)

	return runCore(ctx, cfg, ghClient, agents.RunPipeline, log)
}

// runCore contains the testable orchestration logic. It accepts the pipeline runner
// as a function so it can be tested without requiring an LLM backend.
func runCore(ctx context.Context, cfg *config.Config, ghClient *gh.Client, runPipeline pipelineFunc, log *slog.Logger) error {

	// --- Fetch PR data ---
	log.Info("Fetching PR data...")
	prData, err := ghClient.GetPRData(ctx, cfg.PRNumber)
	if err != nil {
		return fmt.Errorf("fetching PR data: %w", err)
	}

	log.Info("PR data fetched",
		"title", prData.Title,
		"files", prData.ChangedFiles,
		"additions", prData.Additions,
		"deletions", prData.Deletions,
	)

	// --- Filter files ---
	prData.Files = filter.FilterPRFiles(prData.Files, cfg.ExcludeDirectories)
	if len(prData.Files) == 0 {
		log.Info("No files to scan after filtering")
		writeOutput("findings-count", "0")
		return nil
	}

	// --- Fetch diff ---
	log.Info("Fetching PR diff...")
	diff, err := ghClient.GetPRDiff(ctx, cfg.PRNumber)
	if err != nil {
		log.Warn("Failed to fetch diff, will scan without it", "error", err)
	}

	// --- Build prompt ---
	includeDiff := diff != ""
	scanPrompt, err := agents.BuildSecurityAuditPrompt(prData, diff, includeDiff, cfg.CustomScanInstructions)
	if err != nil {
		return fmt.Errorf("building prompt: %w", err)
	}

	// --- Load exceptions ---
	var exceptions []filter.Exception
	if cfg.ExceptionsFile != "" {
		var eerr error
		exceptions, eerr = filter.LoadExceptions(cfg.ExceptionsFile)
		if eerr != nil {
			return fmt.Errorf("loading exceptions: %w", eerr)
		}
		log.Info("Loaded exceptions", "count", len(exceptions))
	}

	// --- Run agent pipeline ---
	pipelineCfg := agents.PipelineConfig{
		APIKey:                      cfg.GoogleAPIKey,
		ScannerModel:                cfg.ScannerModel,
		ValidatorModel:              cfg.ValidatorModel,
		AutofixModel:                cfg.AutofixModel,
		ScanInstruction:             scanPrompt,
		EnableLLMFilter:             cfg.EnableLLMFilter,
		EnableAutofix:               cfg.EnableAutofix,
		CustomFilteringInstructions: cfg.CustomFilteringInstructions,
		Exceptions:                  exceptions,
		Log:                         log,
	}

	result, err := runPipeline(ctx, pipelineCfg)
	// If the scan fails, retry without the diff (fallback for oversized prompts or
	// ADK state-injection failures caused by code braces in the diff).
	if err != nil {
		log.Warn("Pipeline failed, retrying without diff", "error", err)
		scanPrompt, perr := agents.BuildSecurityAuditPrompt(prData, diff, false, cfg.CustomScanInstructions)
		if perr != nil {
			return fmt.Errorf("building fallback prompt: %w", perr)
		}
		pipelineCfg.ScanInstruction = scanPrompt
		result, err = runPipeline(ctx, pipelineCfg)
		if err != nil {
			return fmt.Errorf("pipeline execution (retry): %w", err)
		}
	}

	// --- Output results ---
	log.Info("Scan complete",
		"total_findings", result.Findings.Stats.TotalFindings,
		"kept", result.Findings.Stats.KeptFindings,
		"hard_excluded", result.Findings.Stats.HardExcluded,
		"llm_excluded", result.Findings.Stats.LLMExcluded,
	)

	return outputResults(ctx, cfg, ghClient, prData, result, log)
}

// outputResults writes scan results to disk, sets GitHub Action outputs, posts
// PR comments, and returns errHighSeverity when appropriate.
func outputResults(ctx context.Context, cfg *config.Config, ghClient *gh.Client, prData *gh.PRData, result *findings.PipelineResult, log *slog.Logger) error {
	outputDir := cfg.OutputDir
	if outputDir == "" {
		outputDir = os.TempDir()
	}

	// --- Write results file ---
	var resultsFile string
	switch cfg.OutputFormat {
	case "sarif":
		resultsFile = filepath.Join(outputDir, "barry-results.sarif")
		log.Info("Writing SARIF output", "path", resultsFile)
		if serr := writeSARIF(resultsFile, &result.Findings); serr != nil {
			return fmt.Errorf("writing SARIF results: %w", serr)
		}
	default: // "json"
		resultsFile = filepath.Join(outputDir, "barry-results.json")
		resultsJSON, jerr := json.MarshalIndent(result.Findings, "", "  ")
		if jerr != nil {
			return fmt.Errorf("marshaling results: %w", jerr)
		}
		if werr := os.WriteFile(resultsFile, resultsJSON, 0o644); werr != nil {
			return fmt.Errorf("writing JSON results: %w", werr)
		}
		fmt.Println(string(resultsJSON))
	}

	// Set GitHub Action outputs.
	writeOutput("findings-count", fmt.Sprintf("%d", len(result.Findings.Findings)))
	writeOutput("results-file", resultsFile)

	// --- Post PR comments ---
	if cfg.CommentPR && len(result.Findings.Findings) > 0 {
		log.Info("Posting PR review comments...")
		commitID := cfg.HeadSHA
		if commitID == "" {
			commitID = prData.HeadSHA
		}
		if cerr := comment.PostReview(ctx, ghClient, cfg.PRNumber, commitID, result.Findings.Findings, log); cerr != nil {
			log.Error("Failed to post PR comments", "error", cerr)
			// Don't fail the action — findings were still output.
		}
	}

	// Signal failure if HIGH severity findings exist.
	if slices.ContainsFunc(result.Findings.Findings, func(f findings.Finding) bool {
		return f.Severity == findings.SeverityHigh
	}) {
		return errHighSeverity
	}

	return nil
}

// writeOutput writes a value to $GITHUB_OUTPUT for GitHub Actions.
func writeOutput(name, value string) {
	outputFile := os.Getenv("GITHUB_OUTPUT")
	if outputFile == "" {
		return
	}
	// Sanitize newlines to prevent output injection.
	name = strings.ReplaceAll(strings.ReplaceAll(name, "\n", ""), "\r", "")
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\n", ""), "\r", "")
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck // best-effort output write
	_, _ = fmt.Fprintf(f, "%s=%s\n", name, value)
}

// barryVersion is set at build time via -ldflags.
var barryVersion = "dev"

// writeSARIF writes the SARIF report to the given path.
func writeSARIF(path string, output *findings.ScanOutput) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating SARIF file: %w", err)
	}
	defer f.Close() //nolint:errcheck
	return sarif.WriteReport(f, output, barryVersion)
}

package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/workflowagents/sequentialagent"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/genai"

	"github.com/cosmin/barry/internal/filter"
	"github.com/cosmin/barry/internal/findings"
)

const (
	appName          = "barry"
	validatorAppName = "barry-validator"
	autofixerAppName = "barry-autofixer"
	userID           = "barry-action"
)

// PipelineConfig holds all settings needed to run the scan+filter+validate pipeline.
type PipelineConfig struct {
	APIKey                      string
	ScannerModel                string
	ValidatorModel              string
	AutofixModel                string
	ScanInstruction             string
	EnableLLMFilter             bool
	EnableAutofix               bool
	CustomFilteringInstructions string
	Exceptions                  []filter.Exception
	Log                         *slog.Logger
}

// RunPipeline orchestrates the full security scan:
//  1. Scanner agent analyses the diff and emits structured findings.
//  2. Hard-filter agent removes obvious false positives via regex rules.
//  3. (Optional) Validator agent re-examines each remaining finding with LLM.
//  4. (Optional) Autofixer agent generates a code fix for each remaining finding.
//
// The PR context (diff, file list, security guidelines) is delivered as the user
// message so that ADK's {key} state-injection does not misinterpret code braces
// in diff content as session-state variable references.
func RunPipeline(ctx context.Context, cfg PipelineConfig) (*findings.PipelineResult, error) {
	scannerAgent, err := NewScanner(ctx, cfg.APIKey, cfg.ScannerModel)
	if err != nil {
		return nil, fmt.Errorf("creating scanner agent: %w", err)
	}

	hardFilterAgent, err := NewHardFilter(cfg.Log, cfg.Exceptions)
	if err != nil {
		return nil, fmt.Errorf("creating hard filter agent: %w", err)
	}

	var validatorAgent agent.Agent
	if cfg.EnableLLMFilter {
		validatorAgent, err = NewValidator(ctx, cfg.APIKey, cfg.ValidatorModel)
		if err != nil {
			return nil, fmt.Errorf("creating validator agent: %w", err)
		}
	}

	var autofixerAgent agent.Agent
	if cfg.EnableAutofix {
		autofixerAgent, err = NewAutofixer(ctx, cfg.APIKey, cfg.AutofixModel)
		if err != nil {
			return nil, fmt.Errorf("creating autofixer agent: %w", err)
		}
	}

	return runPipelineCore(ctx, cfg, scannerAgent, hardFilterAgent, validatorAgent, autofixerAgent)
}

// runPipelineCore contains the testable orchestration logic. It accepts pre-built
// agents so it can be tested with real custom agents that don't require an LLM backend.
func runPipelineCore(ctx context.Context, cfg PipelineConfig, scannerAgent, hardFilterAgent, validatorAgent, autofixerAgent agent.Agent) (*findings.PipelineResult, error) {
	log := cfg.Log

	pipeline, err := sequentialagent.New(sequentialagent.Config{
		AgentConfig: agent.Config{
			Name:      "scan_and_filter",
			SubAgents: []agent.Agent{scannerAgent, hardFilterAgent},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating sequential agent: %w", err)
	}

	state, err := runAgent(ctx, appName, pipeline, cfg.ScanInstruction, log)
	if err != nil {
		return nil, err
	}

	keptFindings, statsVal, excludedVal, _, err := readPipelineState(state)
	if err != nil {
		return nil, fmt.Errorf("reading pipeline state: %w", err)
	}

	// --- Phase 3: Optional LLM validation ---
	if cfg.EnableLLMFilter && len(keptFindings) > 0 {
		log.Info("Running LLM validation on remaining findings", "count", len(keptFindings))
		validated, llmExcluded, _ := runValidationCore(ctx, cfg, validatorAgent, keptFindings)
		excludedVal = append(excludedVal, llmExcluded...)
		statsVal.LLMExcluded = len(llmExcluded)
		statsVal.KeptFindings = len(validated)
		keptFindings = validated
	}

	// --- Phase 4: Optional Autofix generation ---
	if cfg.EnableAutofix && len(keptFindings) > 0 {
		log.Info("Running Autofix generation on remaining findings", "count", len(keptFindings))
		keptFindings, _ = runAutofixCore(ctx, cfg, autofixerAgent, keptFindings)
	}

	return &findings.PipelineResult{
		Findings: findings.ScanOutput{
			Findings: keptFindings,
			Stats:    statsVal,
			Excluded: excludedVal,
		},
	}, nil
}

// runAgent creates a runner+session, sends a message, and returns the final session state.
func runAgent(ctx context.Context, app string, a agent.Agent, userMessage string, log *slog.Logger) (session.State, error) {
	sessSvc := session.InMemoryService()
	r, err := runner.New(runner.Config{
		AppName:        app,
		Agent:          a,
		SessionService: sessSvc,
	})
	if err != nil {
		return nil, fmt.Errorf("creating runner: %w", err)
	}

	createResp, err := sessSvc.Create(ctx, &session.CreateRequest{
		AppName: app,
		UserID:  userID,
	})
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}
	sessID := createResp.Session.ID()

	msg := &genai.Content{
		Parts: []*genai.Part{genai.NewPartFromText(userMessage)},
		Role:  "user",
	}

	for evt, err := range r.Run(ctx, userID, sessID, msg, agent.RunConfig{}) {
		if err != nil {
			return nil, fmt.Errorf("agent run error: %w", err)
		}
		if evt != nil && evt.Author != "" {
			log.Info("Pipeline event", "author", evt.Author)
		}
	}

	sess, err := sessSvc.Get(ctx, &session.GetRequest{
		AppName:   app,
		UserID:    userID,
		SessionID: sessID,
	})
	if err != nil {
		return nil, fmt.Errorf("getting session: %w", err)
	}

	return sess.Session.State(), nil
}

func readPipelineState(state session.State) ([]findings.Finding, findings.FilterStats, []findings.ExcludedFinding, findings.AnalysisSummary, error) {
	var keptFindings []findings.Finding
	var stats findings.FilterStats
	var excluded []findings.ExcludedFinding
	var summary findings.AnalysisSummary

	if err := stateUnmarshal(state, StateKeyFilteredFindings, &keptFindings); err != nil {
		return nil, stats, nil, summary, fmt.Errorf("decoding %s: %w", StateKeyFilteredFindings, err)
	}
	if err := stateUnmarshal(state, StateKeyHardFilterStats, &stats); err != nil {
		return nil, stats, nil, summary, fmt.Errorf("decoding %s: %w", StateKeyHardFilterStats, err)
	}
	if err := stateUnmarshal(state, StateKeyHardExcluded, &excluded); err != nil {
		return nil, stats, nil, summary, fmt.Errorf("decoding %s: %w", StateKeyHardExcluded, err)
	}
	if err := stateUnmarshal(state, StateKeyAnalysisSummary, &summary); err != nil {
		return nil, stats, nil, summary, fmt.Errorf("decoding %s: %w", StateKeyAnalysisSummary, err)
	}

	return keptFindings, stats, excluded, summary, nil
}

// decodeStateValue decodes a value retrieved from session state into dst.
// It handles both string values (raw JSON text stored by LLM agents via OutputKey)
// and already-decoded values (maps/slices stored by custom agents).
func decodeStateValue(v any, dst any) error {
	var (
		b   []byte
		err error
	)
	if s, ok := v.(string); ok {
		b = []byte(s)
	} else {
		if b, err = json.Marshal(v); err != nil {
			return err
		}
	}
	return json.Unmarshal(b, dst)
}

// stateUnmarshal reads a key from the session state and JSON-decodes it into dst.
// Returns nil if the key is not present.
func stateUnmarshal(state session.State, key string, dst any) error {
	v, err := state.Get(key)
	if err != nil {
		// Key not present — leave dst at zero value.
		return nil
	}
	if err := decodeStateValue(v, dst); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}

// runValidationCore contains the testable validation loop logic.
func runValidationCore(ctx context.Context, cfg PipelineConfig, validatorAgent agent.Agent, findingsList []findings.Finding) ([]findings.Finding, []findings.ExcludedFinding, error) {
	log := cfg.Log

	var kept []findings.Finding
	var excluded []findings.ExcludedFinding

	for _, f := range findingsList {
		result, err := runAgentOnFinding[findings.ValidationResult](ctx, validatorAgent, cfg, validatorAppName, StateKeyValidationResult, "Analyze this security finding and determine if it is a true positive or false positive", f)
		if err != nil {
			log.Warn("Validation failed for finding, keeping it", "file", f.File, "error", err)
			kept = append(kept, f)
			continue
		}

		if result.KeepFinding {
			kept = append(kept, f)
		} else {
			log.Info("LLM excluded finding", "file", f.File, "reason", result.ExclusionReason)
			excluded = append(excluded, findings.ExcludedFinding{
				Finding: f,
				Reason:  fmt.Sprintf("LLM validation: %s", result.Justification),
			})
		}
	}

	return kept, excluded, nil
}

// runAutofixCore contains the testable autofix loop logic.
func runAutofixCore(ctx context.Context, cfg PipelineConfig, autofixerAgent agent.Agent, findingsList []findings.Finding) ([]findings.Finding, error) {
	log := cfg.Log

	for i, f := range findingsList {
		result, err := runAgentOnFinding[findings.AutofixResult](ctx, autofixerAgent, cfg, autofixerAppName, StateKeyAutofixResult, "Analyze this security finding and provide a code fix", f)
		if err != nil {
			log.Warn("Autofix generation failed for finding, keeping it without fix", "file", f.File, "error", err)
			continue
		}

		if result.Autofix != "" {
			findingsList[i].Autofix = result.Autofix
		}
	}

	return findingsList, nil
}

// runAgentOnFinding marshals a finding, runs an agent with it as a prompt, and
// unmarshals the result from session state. It works for both validation and autofix.
func runAgentOnFinding[T comparable](ctx context.Context, a agent.Agent, cfg PipelineConfig, appName, stateKey, promptPrefix string, f findings.Finding) (*T, error) {
	findingJSON, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling finding: %w", err)
	}
	prompt := fmt.Sprintf("%s:\n\n%s", promptPrefix, string(findingJSON))
	if cfg.CustomFilteringInstructions != "" {
		prompt += fmt.Sprintf("\n\nAdditional filtering instructions:\n%s", cfg.CustomFilteringInstructions)
	}

	state, err := runAgent(ctx, appName, a, prompt, cfg.Log)
	if err != nil {
		return nil, err
	}

	var result T
	if err := stateUnmarshal(state, stateKey, &result); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", stateKey, err)
	}

	var zero T
	if result == zero {
		return nil, errors.New("agent returned no result in session state")
	}

	return &result, nil
}

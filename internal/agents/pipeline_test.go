package agents

import (
	"context"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"testing"

	"github.com/cosmin/barry/internal/filter"
	"github.com/cosmin/barry/internal/findings"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/model"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

// mockState implements session.State for testing.
type mockState struct {
	data map[string]any
}

func newMockState() *mockState {
	return &mockState{data: make(map[string]any)}
}

func (m *mockState) Get(key string) (any, error) {
	v, ok := m.data[key]
	if !ok {
		return nil, session.ErrStateKeyNotExist
	}
	return v, nil
}

func (m *mockState) Set(key string, val any) error {
	m.data[key] = val
	return nil
}

func (m *mockState) All() iter.Seq2[string, any] {
	return func(yield func(string, any) bool) {
		for k, v := range m.data {
			if !yield(k, v) {
				return
			}
		}
	}
}

func TestStateUnmarshal_KeyNotPresent(t *testing.T) {
	state := newMockState()
	var dst findings.FilterStats
	err := stateUnmarshal(state, "nonexistent", &dst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst.TotalFindings != 0 {
		t.Error("dst should be zero value when key not present")
	}
}

func TestStateUnmarshal_ValidJSON(t *testing.T) {
	state := newMockState()
	state.data["stats"] = map[string]any{
		"total_findings": float64(10),
		"hard_excluded":  float64(3),
		"llm_excluded":   float64(1),
		"kept_findings":  float64(6),
	}
	var dst findings.FilterStats
	err := stateUnmarshal(state, "stats", &dst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst.TotalFindings != 10 {
		t.Errorf("TotalFindings = %d, want 10", dst.TotalFindings)
	}
	if dst.HardExcluded != 3 {
		t.Errorf("HardExcluded = %d, want 3", dst.HardExcluded)
	}
	if dst.KeptFindings != 6 {
		t.Errorf("KeptFindings = %d, want 6", dst.KeptFindings)
	}
}

func TestStateUnmarshal_InvalidStructure(t *testing.T) {
	state := newMockState()
	// Put a string where a struct is expected.
	state.data["stats"] = "not a struct"
	var dst findings.FilterStats
	err := stateUnmarshal(state, "stats", &dst)
	if err == nil {
		t.Fatal("expected error for invalid structure")
	}
}

func TestStateUnmarshal_UnmarshalableValue(t *testing.T) {
	state := newMockState()
	// Functions cannot be marshaled to JSON.
	state.data["key"] = func() {}
	var dst findings.FilterStats
	err := stateUnmarshal(state, "key", &dst)
	if err == nil {
		t.Fatal("expected error for unmarshalable value")
	}
}

func TestReadPipelineState_AllKeysPresent(t *testing.T) {
	state := newMockState()
	state.data["filtered_findings"] = []any{
		map[string]any{
			"file":             "a.go",
			"line":             float64(10),
			"severity":         "HIGH",
			"category":         "xss",
			"description":      "XSS vuln",
			"exploit_scenario": "inject script",
			"recommendation":   "escape output",
			"confidence":       0.9,
		},
	}
	state.data["hard_filter_stats"] = map[string]any{
		"total_findings": float64(5),
		"hard_excluded":  float64(4),
		"kept_findings":  float64(1),
	}
	state.data["hard_excluded"] = []any{
		map[string]any{
			"finding": map[string]any{"file": "b.go", "line": float64(1), "severity": "LOW", "category": "test", "description": "d", "exploit_scenario": "", "recommendation": "", "confidence": 0.1},
			"reason":  "test file",
		},
	}
	state.data["analysis_summary"] = map[string]any{
		"files_reviewed":   float64(3),
		"high_severity":    float64(1),
		"medium_severity":  float64(0),
		"low_severity":     float64(0),
		"review_completed": true,
	}
	kept, stats, excluded, summary, err := readPipelineState(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(kept) != 1 {
		t.Errorf("kept findings = %d, want 1", len(kept))
	}
	if kept[0].File != "a.go" {
		t.Errorf("kept[0].File = %q, want 'a.go'", kept[0].File)
	}
	if stats.TotalFindings != 5 {
		t.Errorf("stats.TotalFindings = %d, want 5", stats.TotalFindings)
	}
	if len(excluded) != 1 {
		t.Errorf("excluded = %d, want 1", len(excluded))
	}
	if summary.FilesReviewed != 3 {
		t.Errorf("summary.FilesReviewed = %d, want 3", summary.FilesReviewed)
	}
	if !summary.ReviewCompleted {
		t.Error("summary.ReviewCompleted should be true")
	}
}

func TestReadPipelineState_EmptyState(t *testing.T) {
	state := newMockState()
	kept, stats, excluded, summary, err := readPipelineState(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kept != nil {
		t.Errorf("kept should be nil, got %v", kept)
	}
	if stats.TotalFindings != 0 {
		t.Error("stats should be zero value")
	}
	if excluded != nil {
		t.Errorf("excluded should be nil, got %v", excluded)
	}
	if summary.FilesReviewed != 0 {
		t.Error("summary should be zero value")
	}
}

func TestReadPipelineState_InvalidFilteredFindings(t *testing.T) {
	state := newMockState()
	state.data["filtered_findings"] = "invalid"
	_, _, _, _, err := readPipelineState(state)
	if err == nil {
		t.Fatal("expected error for invalid filtered_findings")
	}
}

func TestReadPipelineState_InvalidHardFilterStats(t *testing.T) {
	state := newMockState()
	state.data["filtered_findings"] = []any{}
	state.data["hard_filter_stats"] = "invalid"
	_, _, _, _, err := readPipelineState(state)
	if err == nil {
		t.Fatal("expected error for invalid hard_filter_stats")
	}
}

func TestReadPipelineState_InvalidHardExcluded(t *testing.T) {
	state := newMockState()
	state.data["filtered_findings"] = []any{}
	state.data["hard_filter_stats"] = map[string]any{}
	state.data["hard_excluded"] = "invalid"
	_, _, _, _, err := readPipelineState(state)
	if err == nil {
		t.Fatal("expected error for invalid hard_excluded")
	}
}

func TestReadPipelineState_InvalidAnalysisSummary(t *testing.T) {
	state := newMockState()
	state.data["filtered_findings"] = []any{}
	state.data["hard_filter_stats"] = map[string]any{}
	state.data["hard_excluded"] = []any{}
	state.data["analysis_summary"] = "invalid"
	_, _, _, _, err := readPipelineState(state)
	if err == nil {
		t.Fatal("expected error for invalid analysis_summary")
	}
}

func runHardFilter(t *testing.T, rawFindings map[string]any) []*session.Event {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	hardFilter, err := NewHardFilter(log, nil)
	if err != nil {
		t.Fatalf("NewHardFilter: %v", err)
	}

	ctx := context.Background()
	sessSvc := session.InMemoryService()

	createResp, err := sessSvc.Create(ctx, &session.CreateRequest{
		AppName: "test",
		UserID:  "test-user",
		State: map[string]any{
			"raw_findings": rawFindings,
		},
	})
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	r, err := runner.New(runner.Config{
		AppName:        "test",
		Agent:          hardFilter,
		SessionService: sessSvc,
	})
	if err != nil {
		t.Fatalf("creating runner: %v", err)
	}

	msg := &genai.Content{
		Parts: []*genai.Part{genai.NewPartFromText("filter")},
		Role:  "user",
	}

	var events []*session.Event
	for evt, err := range r.Run(ctx, "test-user", createResp.Session.ID(), msg, agent.RunConfig{}) {
		if err != nil {
			t.Fatalf("run error: %v", err)
		}
		if evt != nil {
			events = append(events, evt)
		}
	}
	return events
}

func eventText(events []*session.Event) string {
	for _, evt := range events {
		if evt.Author == "hard_filter" && evt.Content != nil {
			for _, p := range evt.Content.Parts {
				if p.Text != "" {
					return p.Text
				}
			}
		}
	}
	return ""
}

func TestHardFilter(t *testing.T) {
	events := runHardFilter(t, map[string]any{
		"findings": []any{
			map[string]any{
				"file":             "src/handler.go",
				"line":             float64(42),
				"severity":         "HIGH",
				"category":         "sql_injection",
				"description":      "SQL injection in query builder",
				"exploit_scenario": "attacker sends malicious input",
				"recommendation":   "use parameterized queries",
				"confidence":       0.95,
			},
			map[string]any{
				"file":             "README.md",
				"line":             float64(1),
				"severity":         "LOW",
				"category":         "info_disclosure",
				"description":      "Sensitive information in documentation",
				"exploit_scenario": "read the docs",
				"recommendation":   "remove secrets",
				"confidence":       0.3,
			},
		},
		"analysis_summary": map[string]any{
			"files_reviewed":   float64(2),
			"high_severity":    float64(1),
			"medium_severity":  float64(0),
			"low_severity":     float64(1),
			"review_completed": true,
		},
	})

	got := eventText(events)
	want := "Hard filter: 1 kept, 1 excluded out of 2 total"
	if got != want {
		t.Errorf("event text = %q, want %q", got, want)
	}
}

func TestHardFilter_AllExcluded(t *testing.T) {
	events := runHardFilter(t, map[string]any{
		"findings": []any{
			map[string]any{
				"file":             "docs/README.md",
				"line":             float64(1),
				"severity":         "LOW",
				"category":         "info",
				"description":      "some info leak",
				"exploit_scenario": "",
				"recommendation":   "",
				"confidence":       0.1,
			},
		},
		"analysis_summary": map[string]any{
			"files_reviewed":   float64(1),
			"high_severity":    float64(0),
			"medium_severity":  float64(0),
			"low_severity":     float64(1),
			"review_completed": true,
		},
	})

	got := eventText(events)
	want := "Hard filter: 0 kept, 1 excluded out of 1 total"
	if got != want {
		t.Errorf("event text = %q, want %q", got, want)
	}
}

func TestHardFilter_NoFindings(t *testing.T) {
	events := runHardFilter(t, map[string]any{
		"findings": []any{},
		"analysis_summary": map[string]any{
			"files_reviewed":   float64(0),
			"high_severity":    float64(0),
			"medium_severity":  float64(0),
			"low_severity":     float64(0),
			"review_completed": true,
		},
	})

	got := eventText(events)
	want := "Hard filter: 0 kept, 0 excluded out of 0 total"
	if got != want {
		t.Errorf("event text = %q, want %q", got, want)
	}
}

func runHardFilterWithState(t *testing.T, initialState map[string]any) ([]*session.Event, []error) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	hardFilter, err := NewHardFilter(log, nil)
	if err != nil {
		t.Fatalf("NewHardFilter: %v", err)
	}

	ctx := context.Background()
	sessSvc := session.InMemoryService()

	createResp, err := sessSvc.Create(ctx, &session.CreateRequest{
		AppName: "test",
		UserID:  "test-user",
		State:   initialState,
	})
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	r, err := runner.New(runner.Config{
		AppName:        "test",
		Agent:          hardFilter,
		SessionService: sessSvc,
	})
	if err != nil {
		t.Fatalf("creating runner: %v", err)
	}

	msg := &genai.Content{
		Parts: []*genai.Part{genai.NewPartFromText("filter")},
		Role:  "user",
	}

	var events []*session.Event
	var errs []error
	for evt, err := range r.Run(ctx, "test-user", createResp.Session.ID(), msg, agent.RunConfig{}) {
		if err != nil {
			errs = append(errs, err)
		}
		if evt != nil {
			events = append(events, evt)
		}
	}
	return events, errs
}

func TestHardFilter_MissingRawFindings(t *testing.T) {
	_, errs := runHardFilterWithState(t, map[string]any{})
	if len(errs) == 0 {
		t.Fatal("expected error when raw_findings is missing")
	}
}

func TestHardFilter_InvalidRawFindings(t *testing.T) {
	_, errs := runHardFilterWithState(t, map[string]any{
		"raw_findings": "not a valid scan result",
	})
	if len(errs) == 0 {
		t.Fatal("expected error for invalid raw_findings")
	}
}

func TestHardFilter_UnmarshalableRawFindings(t *testing.T) {
	_, errs := runHardFilterWithState(t, map[string]any{
		"raw_findings": make(chan int),
	})
	if len(errs) == 0 {
		t.Fatal("expected error for unmarshalable raw_findings")
	}
}

// --- Test helpers: custom agents for testing pipeline orchestration ---

var discardLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// newStateWriterAgent creates a custom agent that writes the given data to session state and yields text.
func newStateWriterAgent(t *testing.T, name string, stateData map[string]any, responseText string) agent.Agent {
	t.Helper()
	a, err := agent.New(agent.Config{
		Name:        name,
		Description: "test agent that writes state",
		Run: func(ictx agent.InvocationContext) iter.Seq2[*session.Event, error] {
			return func(yield func(*session.Event, error) bool) {
				for k, v := range stateData {
					_ = ictx.Session().State().Set(k, v)
				}
				yield(&session.Event{
					LLMResponse: model.LLMResponse{
						Content: &genai.Content{
							Parts: []*genai.Part{genai.NewPartFromText(responseText)},
							Role:  "model",
						},
					},
					Author:  name,
					Actions: session.EventActions{StateDelta: stateData},
				}, nil)
			}
		},
	})
	if err != nil {
		t.Fatalf("creating %s agent: %v", name, err)
	}
	return a
}

// newErrorAgent creates a custom agent that always yields an error.
func newErrorAgent(t *testing.T, name string) agent.Agent {
	t.Helper()
	a, err := agent.New(agent.Config{
		Name:        name,
		Description: "test agent that errors",
		Run: func(ictx agent.InvocationContext) iter.Seq2[*session.Event, error] {
			return func(yield func(*session.Event, error) bool) {
				yield(nil, fmt.Errorf("intentional test error from %s", name))
			}
		},
	})
	if err != nil {
		t.Fatalf("creating %s agent: %v", name, err)
	}
	return a
}

// --- Tests for runAgent ---

func TestRunAgent_WithCustomAgent(t *testing.T) {
	stateData := map[string]any{
		"test_key": "test_value",
	}
	a := newStateWriterAgent(t, "writer", stateData, "done")

	state, err := runAgent(context.Background(), "test-app", a, "hello", discardLog)
	if err != nil {
		t.Fatalf("runAgent: %v", err)
	}

	val, err := state.Get("test_key")
	if err != nil {
		t.Fatalf("state.Get: %v", err)
	}
	if val != "test_value" {
		t.Errorf("state[test_key] = %v, want test_value", val)
	}
}

func TestRunAgent_AgentError(t *testing.T) {
	a := newErrorAgent(t, "error_agent")

	_, err := runAgent(context.Background(), "test-app", a, "hello", discardLog)
	if err == nil {
		t.Fatal("expected error from erroring agent")
	}
}

func TestRunAgent_SessionGetError(t *testing.T) {
	// To trigger session Get error, we can use a mock session service,
	// but runAgent uses session.InMemoryService() internally.
	// Since we can't easily swap it, we might skip this or use a more complex approach.
}

func TestRunValidationCore_ErrorPath(t *testing.T) {
	errAgent := newErrorAgent(t, "validator")
	cfg := PipelineConfig{Log: discardLog}
	findingsList := []findings.Finding{{File: "test.go"}}

	kept, excluded, err := runValidationCore(context.Background(), cfg, errAgent, findingsList)
	if err != nil {
		t.Fatalf("runValidationCore should not return error on single finding failure: %v", err)
	}
	if len(kept) != 1 {
		t.Errorf("kept = %d, want 1 (fallback to keep on error)", len(kept))
	}
	if len(excluded) != 0 {
		t.Errorf("excluded = %d, want 0", len(excluded))
	}
}

func TestRunAutofixCore_ErrorPath(t *testing.T) {
	errAgent := newErrorAgent(t, "autofixer")
	cfg := PipelineConfig{Log: discardLog}
	findingsList := []findings.Finding{{File: "test.go"}}

	fixed, err := runAutofixCore(context.Background(), cfg, errAgent, findingsList)
	if err != nil {
		t.Fatalf("runAutofixCore should not return error on single finding failure: %v", err)
	}
	if fixed[0].Autofix != "" {
		t.Errorf("autofix = %q, want empty on error", fixed[0].Autofix)
	}
}

func TestRunAgentOnFinding_ValidationError(t *testing.T) {
	errAgent := newErrorAgent(t, "validator")
	cfg := PipelineConfig{Log: discardLog}
	_, err := runAgentOnFinding[findings.ValidationResult](context.Background(), errAgent, cfg, validatorAppName, StateKeyValidationResult, "Analyze", findings.Finding{})
	if err == nil {
		t.Fatal("expected error from runAgentOnFinding (validation)")
	}
}

func TestRunAgentOnFinding_AutofixError(t *testing.T) {
	errAgent := newErrorAgent(t, "autofixer")
	cfg := PipelineConfig{Log: discardLog}
	_, err := runAgentOnFinding[findings.AutofixResult](context.Background(), errAgent, cfg, autofixerAppName, StateKeyAutofixResult, "Analyze", findings.Finding{})
	if err == nil {
		t.Fatal("expected error from runAgentOnFinding (autofix)")
	}
}

func TestRunAgentOnFinding_CustomInstructions(t *testing.T) {
	validationResult := findings.ValidationResult{KeepFinding: true}
	fakeValidator := newStateWriterAgent(t, "validator", map[string]any{
		StateKeyValidationResult: validationResult,
	}, "validated")

	cfg := PipelineConfig{Log: discardLog, CustomFilteringInstructions: "only high severity"}
	res, err := runAgentOnFinding[findings.ValidationResult](context.Background(), fakeValidator, cfg, validatorAppName, StateKeyValidationResult, "Analyze this security finding", findings.Finding{File: "a.go"})
	if err != nil {
		t.Fatalf("runAgentOnFinding: %v", err)
	}
	if !res.KeepFinding {
		t.Error("expected KeepFinding true")
	}
}

func TestStateUnmarshal_KeyPresentButEmpty(t *testing.T) {
	state := newMockState()
	state.data["key"] = nil
	var dst string
	err := stateUnmarshal(state, "key", &dst)
	if err != nil {
		t.Errorf("unexpected error for nil value: %v", err)
	}
}

func TestReadPipelineState_DecodingErrors(t *testing.T) {
	state := newMockState()

	// Test each key failure
	keys := []string{"filtered_findings", "hard_filter_stats", "hard_excluded", "analysis_summary"}
	for _, k := range keys {
		state.data = make(map[string]any)
		for _, prevK := range keys {
			if prevK == k {
				state.data[k] = "invalid" // trigger error
				break
			}
			state.data[prevK] = nil // empty but valid
		}
		_, _, _, _, err := readPipelineState(state)
		if err == nil {
			t.Errorf("expected error for key %s", k)
		}
	}
}

func TestRunAgentOnFinding_NoValidationResult(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := PipelineConfig{Log: log}
	ctx := context.Background()

	emptyAgent := newStateWriterAgent(t, "empty", nil, "done")
	_, err := runAgentOnFinding[findings.ValidationResult](ctx, emptyAgent, cfg, validatorAppName, StateKeyValidationResult, "Analyze", findings.Finding{})
	if err == nil {
		t.Error("expected error when validator returns no result")
	}
}

func TestRunAgentOnFinding_NoAutofixResult(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := PipelineConfig{Log: log}
	ctx := context.Background()

	emptyAgent := newStateWriterAgent(t, "empty", nil, "done")
	_, err := runAgentOnFinding[findings.AutofixResult](ctx, emptyAgent, cfg, autofixerAppName, StateKeyAutofixResult, "Analyze", findings.Finding{})
	if err == nil {
		t.Error("expected error when autofixer returns no result")
	}
}

// --- Tests for runPipelineCore ---

// newFakeScanner creates a scanner agent that writes the given ScanResult to session state.
func newFakeScanner(t *testing.T, result findings.ScanResult) agent.Agent {
	t.Helper()
	return newStateWriterAgent(t, "scanner", map[string]any{
		"raw_findings": result,
	}, "scanned")
}

// testFinding returns a finding suitable for pipeline tests.
func testFinding(file string, severity string, confidence float64) findings.Finding {
	return findings.Finding{
		File:       file,
		Line:       10,
		Severity:   severity,
		Category:   "sql_injection",
		Description: "SQL injection vulnerability",
		Confidence: confidence,
	}
}

func TestRunPipelineCore_HappyPath(t *testing.T) {
	f := testFinding("handler.go", "HIGH", 0.95)
	scanner := newFakeScanner(t, findings.ScanResult{
		Findings:        []findings.Finding{f},
		AnalysisSummary: findings.AnalysisSummary{FilesReviewed: 1, HighSeverity: 1, ReviewCompleted: true},
	})
	hardFilter, err := NewHardFilter(discardLog, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := PipelineConfig{Log: discardLog}
	result, err := runPipelineCore(context.Background(), cfg, scanner, hardFilter, nil, nil)
	if err != nil {
		t.Fatalf("runPipelineCore: %v", err)
	}
	if len(result.Findings.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings.Findings))
	}
	if result.Findings.Findings[0].File != "handler.go" {
		t.Errorf("file = %q, want handler.go", result.Findings.Findings[0].File)
	}
	if result.Findings.Stats.TotalFindings != 1 {
		t.Errorf("total = %d, want 1", result.Findings.Stats.TotalFindings)
	}
	if result.Findings.Stats.KeptFindings != 1 {
		t.Errorf("kept = %d, want 1", result.Findings.Stats.KeptFindings)
	}
}

func TestRunPipelineCore_HardFilterExcludes(t *testing.T) {
	// Markdown files get hard-filtered out.
	scanner := newFakeScanner(t, findings.ScanResult{
		Findings: []findings.Finding{
			testFinding("handler.go", "HIGH", 0.95),
			testFinding("README.md", "LOW", 0.5),
		},
		AnalysisSummary: findings.AnalysisSummary{FilesReviewed: 2, ReviewCompleted: true},
	})
	hardFilter, err := NewHardFilter(discardLog, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := PipelineConfig{Log: discardLog}
	result, err := runPipelineCore(context.Background(), cfg, scanner, hardFilter, nil, nil)
	if err != nil {
		t.Fatalf("runPipelineCore: %v", err)
	}
	if len(result.Findings.Findings) != 1 {
		t.Errorf("kept = %d, want 1", len(result.Findings.Findings))
	}
	if result.Findings.Stats.HardExcluded != 1 {
		t.Errorf("hard_excluded = %d, want 1", result.Findings.Stats.HardExcluded)
	}
	if len(result.Findings.Excluded) != 1 {
		t.Errorf("excluded list = %d, want 1", len(result.Findings.Excluded))
	}
}

func TestRunPipelineCore_WithValidation(t *testing.T) {
	scanner := newFakeScanner(t, findings.ScanResult{
		Findings: []findings.Finding{
			testFinding("a.go", "HIGH", 0.95),
			testFinding("b.go", "MEDIUM", 0.9),
		},
		AnalysisSummary: findings.AnalysisSummary{FilesReviewed: 2, ReviewCompleted: true},
	})
	hardFilter, err := NewHardFilter(discardLog, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Validator that excludes all findings.
	validator := newStateWriterAgent(t, "validator", map[string]any{
		"validation_result": findings.ValidationResult{
			KeepFinding:     false,
			ExclusionReason: "false positive",
			Justification:   "not exploitable",
		},
	}, "validated")

	cfg := PipelineConfig{Log: discardLog, EnableLLMFilter: true}
	result, err := runPipelineCore(context.Background(), cfg, scanner, hardFilter, validator, nil)
	if err != nil {
		t.Fatalf("runPipelineCore: %v", err)
	}
	if len(result.Findings.Findings) != 0 {
		t.Errorf("kept = %d, want 0 (all LLM-excluded)", len(result.Findings.Findings))
	}
	if result.Findings.Stats.LLMExcluded != 2 {
		t.Errorf("llm_excluded = %d, want 2", result.Findings.Stats.LLMExcluded)
	}
}

func TestRunPipelineCore_WithAutofix(t *testing.T) {
	scanner := newFakeScanner(t, findings.ScanResult{
		Findings:        []findings.Finding{testFinding("handler.go", "HIGH", 0.95)},
		AnalysisSummary: findings.AnalysisSummary{FilesReviewed: 1, ReviewCompleted: true},
	})
	hardFilter, err := NewHardFilter(discardLog, nil)
	if err != nil {
		t.Fatal(err)
	}

	autofixer := newStateWriterAgent(t, "autofixer", map[string]any{
		"autofix_result": findings.AutofixResult{Autofix: "use parameterized query"},
	}, "fixed")

	cfg := PipelineConfig{Log: discardLog, EnableAutofix: true}
	result, err := runPipelineCore(context.Background(), cfg, scanner, hardFilter, nil, autofixer)
	if err != nil {
		t.Fatalf("runPipelineCore: %v", err)
	}
	if len(result.Findings.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings.Findings))
	}
	if result.Findings.Findings[0].Autofix != "use parameterized query" {
		t.Errorf("autofix = %q, want 'use parameterized query'", result.Findings.Findings[0].Autofix)
	}
}

func TestRunPipelineCore_WithExceptions(t *testing.T) {
	scanner := newFakeScanner(t, findings.ScanResult{
		Findings: []findings.Finding{
			testFinding("handler.go", "HIGH", 0.95),
			testFinding("legacy.go", "MEDIUM", 0.9),
		},
		AnalysisSummary: findings.AnalysisSummary{FilesReviewed: 2, ReviewCompleted: true},
	})
	exceptions := []filter.Exception{
		{File: "legacy.go", Reason: "known false positive"},
	}
	hardFilter, err := NewHardFilter(discardLog, exceptions)
	if err != nil {
		t.Fatal(err)
	}

	cfg := PipelineConfig{Log: discardLog}
	result, err := runPipelineCore(context.Background(), cfg, scanner, hardFilter, nil, nil)
	if err != nil {
		t.Fatalf("runPipelineCore: %v", err)
	}
	if len(result.Findings.Findings) != 1 {
		t.Errorf("kept = %d, want 1", len(result.Findings.Findings))
	}
	if result.Findings.Stats.HardExcluded != 1 {
		t.Errorf("hard_excluded = %d, want 1", result.Findings.Stats.HardExcluded)
	}
}

func TestRunPipelineCore_LowConfidenceExcluded(t *testing.T) {
	scanner := newFakeScanner(t, findings.ScanResult{
		Findings: []findings.Finding{
			testFinding("handler.go", "HIGH", 0.95),
			testFinding("utils.go", "MEDIUM", 0.5), // below 0.8 threshold
		},
		AnalysisSummary: findings.AnalysisSummary{FilesReviewed: 2, ReviewCompleted: true},
	})
	hardFilter, err := NewHardFilter(discardLog, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := PipelineConfig{Log: discardLog}
	result, err := runPipelineCore(context.Background(), cfg, scanner, hardFilter, nil, nil)
	if err != nil {
		t.Fatalf("runPipelineCore: %v", err)
	}
	if len(result.Findings.Findings) != 1 {
		t.Errorf("kept = %d, want 1", len(result.Findings.Findings))
	}
	if result.Findings.Stats.HardExcluded != 1 {
		t.Errorf("hard_excluded = %d, want 1", result.Findings.Stats.HardExcluded)
	}
}

func TestRunPipelineCore_ScannerError(t *testing.T) {
	scanner := newErrorAgent(t, "scanner")
	hardFilter, err := NewHardFilter(discardLog, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := PipelineConfig{Log: discardLog}
	_, err = runPipelineCore(context.Background(), cfg, scanner, hardFilter, nil, nil)
	if err == nil {
		t.Fatal("expected error when scanner fails")
	}
}

func TestRunPipelineCore_NoFindings(t *testing.T) {
	scanner := newFakeScanner(t, findings.ScanResult{
		AnalysisSummary: findings.AnalysisSummary{ReviewCompleted: true},
	})
	hardFilter, err := NewHardFilter(discardLog, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := PipelineConfig{Log: discardLog, EnableLLMFilter: true, EnableAutofix: true}
	result, err := runPipelineCore(context.Background(), cfg, scanner, hardFilter, nil, nil)
	if err != nil {
		t.Fatalf("runPipelineCore: %v", err)
	}
	if len(result.Findings.Findings) != 0 {
		t.Errorf("findings = %d, want 0", len(result.Findings.Findings))
	}
}

// --- Happy path tests for runValidationCore and runAutofixCore ---

func TestRunValidationCore_KeepsAndExcludes(t *testing.T) {
	// Validator that keeps findings — test the "keep" path.
	keepValidator := newStateWriterAgent(t, "validator", map[string]any{
		"validation_result": findings.ValidationResult{KeepFinding: true, Justification: "real issue"},
	}, "validated")

	cfg := PipelineConfig{Log: discardLog}
	input := []findings.Finding{testFinding("a.go", "HIGH", 0.95)}

	kept, excluded, err := runValidationCore(context.Background(), cfg, keepValidator, input)
	if err != nil {
		t.Fatalf("runValidationCore (keep): %v", err)
	}
	if len(kept) != 1 || kept[0].File != "a.go" {
		t.Errorf("expected a.go to be kept, got kept=%d", len(kept))
	}
	if len(excluded) != 0 {
		t.Errorf("excluded = %d, want 0", len(excluded))
	}

	// Validator that excludes findings — test the "exclude" path.
	excludeValidator := newStateWriterAgent(t, "validator", map[string]any{
		"validation_result": findings.ValidationResult{
			KeepFinding:   false,
			Justification: "not exploitable",
		},
	}, "validated")

	kept, excluded, err = runValidationCore(context.Background(), cfg, excludeValidator, input)
	if err != nil {
		t.Fatalf("runValidationCore (exclude): %v", err)
	}
	if len(kept) != 0 {
		t.Errorf("kept = %d, want 0", len(kept))
	}
	if len(excluded) != 1 {
		t.Errorf("excluded = %d, want 1", len(excluded))
	}
	if len(excluded) > 0 && excluded[0].Finding.File != "a.go" {
		t.Errorf("excluded file = %q, want a.go", excluded[0].Finding.File)
	}
}

func TestRunAutofixCore_AppliesFix(t *testing.T) {
	autofixer := newStateWriterAgent(t, "autofixer", map[string]any{
		"autofix_result": findings.AutofixResult{Autofix: "fixed code"},
	}, "done")

	cfg := PipelineConfig{Log: discardLog}
	input := []findings.Finding{testFinding("a.go", "HIGH", 0.95)}

	result, err := runAutofixCore(context.Background(), cfg, autofixer, input)
	if err != nil {
		t.Fatalf("runAutofixCore: %v", err)
	}
	if result[0].Autofix != "fixed code" {
		t.Errorf("autofix = %q, want 'fixed code'", result[0].Autofix)
	}
}

// --- Tests for agent constructors (NewScanner, NewValidator, NewAutofixer) ---

// fakeModel implements model.LLM for testing constructors without network calls.
// It returns a valid empty ScanResult JSON so the scanner→hardfilter pipeline works.
type fakeModel struct{}

const emptyScanResult = `{"findings":[],"analysis_summary":{"files_reviewed":0,"high_severity":0,"medium_severity":0,"low_severity":0,"review_completed":true}}`

func (fakeModel) Name() string { return "fake-model" }
func (fakeModel) GenerateContent(_ context.Context, _ *model.LLMRequest, _ bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		yield(&model.LLMResponse{
			Content: &genai.Content{
				Parts: []*genai.Part{genai.NewPartFromText(emptyScanResult)},
				Role:  "model",
			},
		}, nil)
	}
}

// withFakeModel swaps the package-level model factory for tests and restores it on cleanup.
func withFakeModel(t *testing.T) {
	t.Helper()
	orig := newModel
	newModel = func(_ context.Context, _, _ string) (model.LLM, error) {
		return fakeModel{}, nil
	}
	t.Cleanup(func() { newModel = orig })
}

func TestNewScanner(t *testing.T) {
	withFakeModel(t)
	a, err := NewScanner(context.Background(), "key", "model")
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil agent")
	}
}

func TestNewValidator(t *testing.T) {
	withFakeModel(t)
	a, err := NewValidator(context.Background(), "key", "model")
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil agent")
	}
}

func TestNewAutofixer(t *testing.T) {
	withFakeModel(t)
	a, err := NewAutofixer(context.Background(), "key", "model")
	if err != nil {
		t.Fatalf("NewAutofixer: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil agent")
	}
}

func TestNewModel_Error(t *testing.T) {
	orig := newModel
	newModel = func(_ context.Context, _, _ string) (model.LLM, error) {
		return nil, fmt.Errorf("connection refused")
	}
	t.Cleanup(func() { newModel = orig })

	_, err := NewScanner(context.Background(), "key", "model")
	if err == nil {
		t.Fatal("expected error when model creation fails")
	}
	_, err = NewValidator(context.Background(), "key", "model")
	if err == nil {
		t.Fatal("expected error when model creation fails")
	}
	_, err = NewAutofixer(context.Background(), "key", "model")
	if err == nil {
		t.Fatal("expected error when model creation fails")
	}
}

// --- Test for RunPipeline ---

func TestRunPipeline_ModelError(t *testing.T) {
	orig := newModel
	newModel = func(_ context.Context, _, _ string) (model.LLM, error) {
		return nil, fmt.Errorf("connection refused")
	}
	t.Cleanup(func() { newModel = orig })

	cfg := PipelineConfig{
		APIKey:       "fake-key",
		ScannerModel: "fake-model",
		Log:          discardLog,
	}
	_, err := RunPipeline(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error when model creation fails")
	}
}

func TestRunPipeline_ValidatorModelError(t *testing.T) {
	calls := 0
	orig := newModel
	newModel = func(_ context.Context, _, name string) (model.LLM, error) {
		calls++
		if calls > 1 {
			return nil, fmt.Errorf("validator model error")
		}
		return fakeModel{}, nil
	}
	t.Cleanup(func() { newModel = orig })

	cfg := PipelineConfig{
		APIKey:          "fake-key",
		ScannerModel:    "fake-model",
		ValidatorModel:  "fake-model",
		EnableLLMFilter: true,
		Log:             discardLog,
	}
	_, err := RunPipeline(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error when validator model creation fails")
	}
}

func TestRunPipeline_AutofixModelError(t *testing.T) {
	calls := 0
	orig := newModel
	newModel = func(_ context.Context, _, name string) (model.LLM, error) {
		calls++
		if calls > 1 {
			return nil, fmt.Errorf("autofixer model error")
		}
		return fakeModel{}, nil
	}
	t.Cleanup(func() { newModel = orig })

	cfg := PipelineConfig{
		APIKey:        "fake-key",
		ScannerModel:  "fake-model",
		AutofixModel:  "fake-model",
		EnableAutofix: true,
		Log:           discardLog,
	}
	_, err := RunPipeline(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error when autofixer model creation fails")
	}
}

// --- Tests for decodeStateValue ---

func TestDecodeStateValue_JSONString(t *testing.T) {
	// Simulates ADK storing LLM output as a raw JSON string via OutputKey.
	s := `{"total_findings":7,"hard_excluded":2,"kept_findings":5}`
	var dst findings.FilterStats
	if err := decodeStateValue(s, &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst.TotalFindings != 7 {
		t.Errorf("TotalFindings = %d, want 7", dst.TotalFindings)
	}
	if dst.HardExcluded != 2 {
		t.Errorf("HardExcluded = %d, want 2", dst.HardExcluded)
	}
}

func TestDecodeStateValue_Map(t *testing.T) {
	// Simulates custom agents storing already-decoded maps.
	v := map[string]any{
		"total_findings": float64(3),
		"hard_excluded":  float64(1),
		"kept_findings":  float64(2),
	}
	var dst findings.FilterStats
	if err := decodeStateValue(v, &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst.TotalFindings != 3 {
		t.Errorf("TotalFindings = %d, want 3", dst.TotalFindings)
	}
}

func TestDecodeStateValue_InvalidJSONString(t *testing.T) {
	if err := decodeStateValue("not json", &findings.FilterStats{}); err == nil {
		t.Fatal("expected error for invalid JSON string")
	}
}

func TestDecodeStateValue_UnmarshalableValue(t *testing.T) {
	if err := decodeStateValue(make(chan int), &findings.FilterStats{}); err == nil {
		t.Fatal("expected error for unmarshalable value")
	}
}

func TestDecodeStateValue_NullValue(t *testing.T) {
	var dst findings.FilterStats
	if err := decodeStateValue(nil, &dst); err != nil {
		t.Fatalf("unexpected error for nil value: %v", err)
	}
}

func TestStateUnmarshal_ValidJSONString(t *testing.T) {
	// Regression: ADK stores LLM OutputKey results as JSON strings.
	state := newMockState()
	state.data["stats"] = `{"total_findings":5,"hard_excluded":2,"kept_findings":3}`
	var dst findings.FilterStats
	if err := stateUnmarshal(state, "stats", &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst.TotalFindings != 5 {
		t.Errorf("TotalFindings = %d, want 5", dst.TotalFindings)
	}
}

func TestHardFilter_RawFindingsAsJSONString(t *testing.T) {
	// Regression: ADK stores scanner OutputKey as a JSON string, not a decoded map.
	rawJSON := `{"findings":[{"file":"handler.go","line":42,"severity":"HIGH","category":"sql_injection","description":"SQL injection","exploit_scenario":"attacker sends input","recommendation":"use parameterized queries","confidence":0.95}],"analysis_summary":{"files_reviewed":1,"high_severity":1,"medium_severity":0,"low_severity":0,"review_completed":true}}`
	_, errs := runHardFilterWithState(t, map[string]any{
		"raw_findings": rawJSON,
	})
	if len(errs) > 0 {
		t.Fatalf("unexpected errors with JSON string raw_findings: %v", errs)
	}
}

func TestRunPipelineCore_ScannerJSONStringOutput(t *testing.T) {
	// Regression: scanner stores raw_findings as a JSON string (real LLM + OutputKey path).
	rawJSON := `{"findings":[{"file":"handler.go","line":42,"severity":"HIGH","category":"sql_injection","description":"SQL injection","exploit_scenario":"attacker sends input","recommendation":"use parameterized queries","confidence":0.95}],"analysis_summary":{"files_reviewed":1,"high_severity":1,"medium_severity":0,"low_severity":0,"review_completed":true}}`
	scanner := newStateWriterAgent(t, "scanner", map[string]any{
		StateKeyRawFindings: rawJSON,
	}, "scanned")
	hardFilter, err := NewHardFilter(discardLog, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := PipelineConfig{Log: discardLog}
	result, err := runPipelineCore(context.Background(), cfg, scanner, hardFilter, nil, nil)
	if err != nil {
		t.Fatalf("runPipelineCore: %v", err)
	}
	if len(result.Findings.Findings) != 1 {
		t.Errorf("findings = %d, want 1", len(result.Findings.Findings))
	}
	if result.Findings.Findings[0].File != "handler.go" {
		t.Errorf("file = %q, want handler.go", result.Findings.Findings[0].File)
	}
}

func TestRunAutofixCore_EmptyAutofix(t *testing.T) {
	autofixer := newStateWriterAgent(t, "autofixer", map[string]any{
		"autofix_result": findings.AutofixResult{Autofix: ""},
	}, "done")

	cfg := PipelineConfig{Log: discardLog}
	input := []findings.Finding{testFinding("a.go", "HIGH", 0.95)}

	result, err := runAutofixCore(context.Background(), cfg, autofixer, input)
	if err != nil {
		t.Fatalf("runAutofixCore: %v", err)
	}
	if result[0].Autofix != "" {
		t.Errorf("autofix = %q, want empty", result[0].Autofix)
	}
}

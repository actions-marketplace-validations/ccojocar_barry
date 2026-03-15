package agents

import (
	"fmt"
	"iter"
	"log/slog"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/model"
	"google.golang.org/adk/session"
	"google.golang.org/genai"

	"github.com/cosmin/barry/internal/filter"
	"github.com/cosmin/barry/internal/findings"
)

const confidenceThreshold = 0.8

// NewHardFilter returns a custom agent that applies regex-based hard exclusion
// rules and user-defined exceptions to findings, removing obvious false positives
// without using the LLM.
func NewHardFilter(log *slog.Logger, exceptions []filter.Exception) (agent.Agent, error) {
	return agent.New(agent.Config{
		Name:        "hard_filter",
		Description: "Applies deterministic hard exclusion rules to filter obvious false positives",
		Run:         makeHardFilterRun(log, exceptions),
	})
}

// classifyFinding returns an exclusion reason if the finding should be excluded,
// or an empty string if it should be kept.
func classifyFinding(f *findings.Finding, exceptions []filter.Exception) string {
	if reason := filter.GetExclusionReason(f); reason != "" {
		return reason
	}
	if reason := filter.MatchException(f, exceptions); reason != "" {
		return reason
	}
	if f.Confidence < confidenceThreshold {
		return fmt.Sprintf("confidence %.2f below threshold %.1f", f.Confidence, confidenceThreshold)
	}
	return ""
}

func makeHardFilterRun(log *slog.Logger, exceptions []filter.Exception) func(agent.InvocationContext) iter.Seq2[*session.Event, error] {
	return func(ictx agent.InvocationContext) iter.Seq2[*session.Event, error] {
		return func(yield func(*session.Event, error) bool) {

			rawVal, err := ictx.Session().State().Get(StateKeyRawFindings)
			if err != nil {
				yield(nil, fmt.Errorf("getting raw_findings from state: %w", err))
				return
			}

			var scanResult findings.ScanResult
			if err := decodeStateValue(rawVal, &scanResult); err != nil {
				yield(nil, fmt.Errorf("parsing raw_findings: %w", err))
				return
			}

			var kept []findings.Finding
			var excluded []findings.ExcludedFinding
			for _, f := range scanResult.Findings {
				if reason := classifyFinding(&f, exceptions); reason != "" {
					log.Info("Hard-excluded finding", "file", f.File, "reason", reason)
					excluded = append(excluded, findings.ExcludedFinding{Finding: f, Reason: reason})
				} else {
					kept = append(kept, f)
				}
			}

			stats := findings.FilterStats{
				TotalFindings: len(scanResult.Findings),
				HardExcluded:  len(excluded),
				KeptFindings:  len(kept),
			}

			log.Info("Hard filter complete",
				"total", stats.TotalFindings,
				"excluded", stats.HardExcluded,
				"kept", stats.KeptFindings,
			)

			// Write results to session state for the next agent.
			stateUpdates := map[string]any{
				StateKeyFilteredFindings: kept,
				StateKeyHardExcluded:     excluded,
				StateKeyHardFilterStats:  stats,
				StateKeyAnalysisSummary:  scanResult.AnalysisSummary,
			}
			for k, v := range stateUpdates {
				if err := ictx.Session().State().Set(k, v); err != nil {
					log.Warn("Failed to set state", "key", k, "error", err)
				}
			}

			msg := fmt.Sprintf("Hard filter: %d kept, %d excluded out of %d total", len(kept), len(excluded), len(scanResult.Findings))
			yield(&session.Event{
				LLMResponse: model.LLMResponse{
					Content: &genai.Content{
						Parts: []*genai.Part{genai.NewPartFromText(msg)},
						Role:  "model",
					},
				},
				Author:  "hard_filter",
				Actions: session.EventActions{StateDelta: stateUpdates},
			}, nil)
		}
	}
}

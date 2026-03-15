package agents

import (
	"context"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"

	"github.com/cosmin/barry/internal/findings"
)

// scannerInstruction is a short static system prompt for the scanner agent.
// The full PR context (diff, file list, guidelines) is delivered via the user
// message so that ADK's {key} state-injection does not misinterpret code braces
// in the diff as session-state references.
const scannerInstruction = "You are a senior security engineer. " +
	"Analyze the GitHub Pull Request provided in the user message for security vulnerabilities. " +
	"Return your findings in the required structured JSON format."

// NewScanner creates an LLM agent that scans PR diffs for security vulnerabilities.
// The full PR context is passed as the user message at run time, not here.
// OutputSchema constrains the response to valid ScanResult JSON.
func NewScanner(ctx context.Context, apiKey, modelName string) (agent.Agent, error) {
	mdl, err := newModel(ctx, apiKey, modelName)
	if err != nil {
		return nil, err
	}

	return llmagent.New(llmagent.Config{
		Name:         "scanner",
		Description:  "Scans PR code changes for security vulnerabilities",
		Model:        mdl,
		Instruction:  scannerInstruction,
		OutputSchema: findings.ScanResultSchema(),
		OutputKey:    StateKeyRawFindings,
	})
}

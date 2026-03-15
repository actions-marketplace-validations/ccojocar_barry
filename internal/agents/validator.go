package agents

import (
	"context"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"

	"github.com/cosmin/barry/internal/findings"
	"github.com/cosmin/barry/internal/prompts"
)

// NewValidator creates an LLM agent that validates individual findings,
// determining whether they are true positives or false positives.
func NewValidator(ctx context.Context, apiKey, modelName string) (agent.Agent, error) {
	mdl, err := newModel(ctx, apiKey, modelName)
	if err != nil {
		return nil, err
	}

	return llmagent.New(llmagent.Config{
		Name:         "validator",
		Description:  "Validates individual security findings to filter false positives",
		Model:        mdl,
		Instruction:  prompts.ValidatorInstructions,
		OutputSchema: findings.ValidationResultSchema(),
		OutputKey:    StateKeyValidationResult,
	})
}

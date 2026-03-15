package agents

import (
	"context"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"

	"github.com/cosmin/barry/internal/findings"
	"github.com/cosmin/barry/internal/prompts"
)

// NewAutofixer creates an LLM agent that generates code fixes for findings.
func NewAutofixer(ctx context.Context, apiKey, modelName string) (agent.Agent, error) {
	mdl, err := newModel(ctx, apiKey, modelName)
	if err != nil {
		return nil, err
	}

	return llmagent.New(llmagent.Config{
		Name:         "autofixer",
		Description:  "Generates code fixes for individual security findings",
		Model:        mdl,
		Instruction:  prompts.AutofixerInstructions,
		OutputSchema: findings.AutofixResultSchema(),
		OutputKey:    StateKeyAutofixResult,
	})
}

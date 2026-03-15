package agents

import (
	"context"

	"google.golang.org/adk/model"
	"google.golang.org/adk/model/gemini"
	"google.golang.org/genai"
)

// modelFactory creates a model.LLM from an API key and model name.
type modelFactory func(ctx context.Context, apiKey, modelName string) (model.LLM, error)

// newModel is the package-level model factory, replaceable in tests.
var newModel modelFactory = newGeminiModel

// newGeminiModel creates a Gemini model instance with the given API key and model name.
func newGeminiModel(ctx context.Context, apiKey, modelName string) (model.LLM, error) {
	return gemini.NewModel(ctx, modelName, &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})
}

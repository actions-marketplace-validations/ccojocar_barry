package agents

import (
	"fmt"
	"strings"
	"text/template"

	ghTypes "github.com/cosmin/barry/internal/github"
	"github.com/cosmin/barry/internal/prompts"
)

// parsedTemplate is the compiled template, parsed once at init time.
var parsedTemplate = template.Must(template.New("security_audit").Parse(prompts.SecurityAudit))

// PromptParams holds the dynamic values injected into the security audit template.
type PromptParams struct {
	PRNumber         int
	PRTitle          string
	RepoFullName     string
	Author           string
	FilesChanged     int
	LinesAdded       int
	LinesDeleted     int
	FileList         string
	DiffSection      string
	CustomCategories string
}

// BuildSecurityAuditPrompt renders the embedded markdown template with PR data.
func BuildSecurityAuditPrompt(pr *ghTypes.PRData, diff string, includeDiff bool, customScanInstructions string) (string, error) {
	// Build file list
	var fileLines []string
	for _, f := range pr.Files {
		fileLines = append(fileLines, fmt.Sprintf("- %s", f.Filename))
	}

	// Build diff section
	var diffSection string
	switch {
	case includeDiff && diff != "":
		diffSection = fmt.Sprintf("\nPR DIFF CONTENT:\n```\n%s\n```\n\nReview the complete diff above. This contains all code changes in the PR.\n", diff)
	case !includeDiff && diff != "":
		diffSection = "\nNOTE: PR diff was omitted due to size constraints. Please use the file exploration tools to examine the specific files that were changed in this PR.\n"
	}

	// Custom categories
	var customCategories string
	if customScanInstructions != "" {
		customCategories = "\n" + customScanInstructions + "\n"
	}

	params := PromptParams{
		PRNumber:         pr.Number,
		PRTitle:          pr.Title,
		RepoFullName:     pr.RepoFullName,
		Author:           pr.Author,
		FilesChanged:     pr.ChangedFiles,
		LinesAdded:       pr.Additions,
		LinesDeleted:     pr.Deletions,
		FileList:         strings.Join(fileLines, "\n"),
		DiffSection:      diffSection,
		CustomCategories: customCategories,
	}

	tmpl := parsedTemplate

	var buf strings.Builder
	if err := tmpl.Execute(&buf, params); err != nil {
		return "", fmt.Errorf("executing prompt template: %w", err)
	}

	return buf.String(), nil
}

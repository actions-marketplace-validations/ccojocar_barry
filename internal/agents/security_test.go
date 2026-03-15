package agents

import (
	"strings"
	"testing"

	ghTypes "github.com/cosmin/barry/internal/github"
)

func basePRData() *ghTypes.PRData {
	return &ghTypes.PRData{
		Number:       10,
		Title:        "Fix auth bug",
		RepoFullName: "owner/repo",
		Author:       "dev",
		ChangedFiles: 2,
		Additions:    30,
		Deletions:    5,
		Files: []ghTypes.PRFile{
			{Filename: "src/main.go"},
			{Filename: "src/auth.go"},
		},
	}
}

func TestBuildSecurityAuditPrompt_WithDiffIncluded(t *testing.T) {
	pr := basePRData()
	diff := "diff --git a/src/main.go b/src/main.go\n+some change"
	got, err := BuildSecurityAuditPrompt(pr, diff, true, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checks := []string{
		"PR #10",
		"Fix auth bug",
		"owner/repo",
		"- src/main.go",
		"- src/auth.go",
		"PR DIFF CONTENT:",
		"diff --git a/src/main.go",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

func TestBuildSecurityAuditPrompt_DiffOmitted(t *testing.T) {
	pr := basePRData()
	diff := "some diff content"
	got, err := BuildSecurityAuditPrompt(pr, diff, false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "omitted due to size constraints") {
		t.Error("prompt should mention diff was omitted")
	}
	if strings.Contains(got, "PR DIFF CONTENT:") {
		t.Error("prompt should not contain diff content when includeDiff=false")
	}
}

func TestBuildSecurityAuditPrompt_NoDiff(t *testing.T) {
	pr := basePRData()
	got, err := BuildSecurityAuditPrompt(pr, "", false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(got, "DIFF") {
		t.Error("prompt should not mention diff when empty")
	}
}

func TestBuildSecurityAuditPrompt_CustomInstructions(t *testing.T) {
	pr := basePRData()
	got, err := BuildSecurityAuditPrompt(pr, "", false, "Check for OWASP Top 10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "Check for OWASP Top 10") {
		t.Error("prompt should include custom scan instructions")
	}
}

func TestBuildSecurityAuditPrompt_EmptyFilesList(t *testing.T) {
	pr := basePRData()
	pr.Files = nil
	got, err := BuildSecurityAuditPrompt(pr, "", false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "PR #10") {
		t.Error("prompt should still contain PR metadata")
	}
}

package comment

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/cosmin/barry/internal/findings"
	gh "github.com/cosmin/barry/internal/github"
)

// mockReviewer implements the Reviewer interface for testing.
type mockReviewer struct {
	existingReview    bool
	existingReviewErr error
	postCalled        bool
	postedComments    []gh.ReviewComment
	postErr           error
}

func (m *mockReviewer) HasExistingReview(_ context.Context, _ int) (bool, error) {
	return m.existingReview, m.existingReviewErr
}

func (m *mockReviewer) PostReviewComments(_ context.Context, _ int, _ string, comments []gh.ReviewComment) error {
	m.postCalled = true
	m.postedComments = comments
	return m.postErr
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestPostReview_EmptyFindings(t *testing.T) {
	m := &mockReviewer{}
	err := PostReview(context.Background(), m, 1, "sha", nil, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.postCalled {
		t.Error("PostReviewComments should not be called with empty findings")
	}
}

func TestPostReview_ExistingReviewSkips(t *testing.T) {
	m := &mockReviewer{existingReview: true}
	fList := []findings.Finding{{File: "a.go", Line: 1, Severity: "HIGH", Description: "test"}}
	err := PostReview(context.Background(), m, 1, "sha", fList, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.postCalled {
		t.Error("PostReviewComments should not be called when review already exists")
	}
}

func TestPostReview_ExistingReviewCheckErrorContinues(t *testing.T) {
	m := &mockReviewer{existingReviewErr: errors.New("api error")}
	fList := []findings.Finding{{File: "a.go", Line: 1, Severity: "HIGH", Description: "test"}}
	err := PostReview(context.Background(), m, 1, "sha", fList, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.postCalled {
		t.Error("PostReviewComments should still be called when HasExistingReview errors")
	}
}

func TestPostReview_FiltersInvalidFileOrLine(t *testing.T) {
	m := &mockReviewer{}
	fList := []findings.Finding{
		{File: "", Line: 10, Description: "no file"},
		{File: "a.go", Line: 0, Description: "no line"},
		{File: "b.go", Line: 5, Description: "valid", Severity: "HIGH"},
	}
	err := PostReview(context.Background(), m, 1, "sha", fList, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.postedComments) != 1 {
		t.Fatalf("expected 1 comment, got %d", len(m.postedComments))
	}
	if m.postedComments[0].Path != "b.go" {
		t.Errorf("comment path = %q, want 'b.go'", m.postedComments[0].Path)
	}
}

func TestPostReview_AllFilteredOut(t *testing.T) {
	m := &mockReviewer{}
	fList := []findings.Finding{
		{File: "", Line: 0, Description: "bad1"},
		{File: "a.go", Line: 0, Description: "bad2"},
	}
	err := PostReview(context.Background(), m, 1, "sha", fList, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.postCalled {
		t.Error("PostReviewComments should not be called when all findings are filtered out")
	}
}

func TestPostReview_HappyPath(t *testing.T) {
	m := &mockReviewer{}
	fList := []findings.Finding{
		{File: "a.go", Line: 10, Description: "issue1", Severity: "HIGH", Category: "xss", Confidence: 0.9},
		{File: "b.go", Line: 20, Description: "issue2", Severity: "MEDIUM", Category: "sqli", Confidence: 0.8},
	}
	err := PostReview(context.Background(), m, 1, "sha", fList, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.postCalled {
		t.Fatal("PostReviewComments should be called")
	}
	if len(m.postedComments) != 2 {
		t.Fatalf("expected 2 comments, got %d", len(m.postedComments))
	}
	if m.postedComments[0].Line != 10 || m.postedComments[1].Line != 20 {
		t.Error("comment lines mismatch")
	}
}

func TestPostReview_PostError(t *testing.T) {
	m := &mockReviewer{postErr: errors.New("post failed")}
	fList := []findings.Finding{{File: "a.go", Line: 1, Description: "test", Severity: "HIGH"}}
	err := PostReview(context.Background(), m, 1, "sha", fList, discardLogger())
	if err == nil || !strings.Contains(err.Error(), "post failed") {
		t.Errorf("expected post error, got: %v", err)
	}
}

func TestFormatFindingComment(t *testing.T) {
	f := &findings.Finding{
		File:            "auth.go",
		Line:            42,
		Severity:        "HIGH",
		Category:        "sql_injection",
		Description:     "SQL injection in login query",
		ExploitScenario: "Attacker supplies malicious username",
		Recommendation:  "Use parameterized queries",
		Confidence:      0.95,
	}

	got := FormatFindingComment(f)

	checks := []string{
		"**Security Issue: SQL injection in login query**",
		"**Severity:** HIGH",
		"**Category:** sql_injection",
		"**Confidence:** 95%",
		"**Exploit Scenario:**",
		"Attacker supplies malicious username",
		"**Recommendation:**",
		"Use parameterized queries",
		"Barry AI Security Analysis",
	}

	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("FormatFindingComment() missing %q", want)
		}
	}
}

func TestFormatFindingCommentMinimal(t *testing.T) {
	f := &findings.Finding{
		File:        "app.py",
		Line:        10,
		Severity:    "LOW",
		Category:    "info_leak",
		Description: "Debug info exposed",
		Confidence:  0.5,
	}

	got := FormatFindingComment(f)

	if strings.Contains(got, "Exploit Scenario") {
		t.Error("should not contain Exploit Scenario when empty")
	}
	if strings.Contains(got, "Recommendation") {
		t.Error("should not contain Recommendation when empty")
	}
	if !strings.Contains(got, "**Confidence:** 50%") {
		t.Error("missing confidence percentage")
	}
}

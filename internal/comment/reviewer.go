package comment

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cosmin/barry/internal/findings"
	gh "github.com/cosmin/barry/internal/github"
)

// Reviewer is the subset of github.Client methods needed by PostReview.
type Reviewer interface {
	HasExistingReview(ctx context.Context, prNumber int) (bool, error)
	PostReviewComments(ctx context.Context, prNumber int, commitID string, comments []gh.ReviewComment) error
}

// FormatFindingComment renders a single finding as a Markdown PR comment.
func FormatFindingComment(f *findings.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🤖 **Security Issue: %s**\n\n", f.Description)
	fmt.Fprintf(&b, "**Severity:** %s\n", f.Severity)
	fmt.Fprintf(&b, "**Category:** %s\n", f.Category)
	fmt.Fprintf(&b, "**Confidence:** %.0f%%\n", f.Confidence*100)
	b.WriteString("**Tool:** Barry AI Security Analysis (Gemini)\n\n")
	if f.ExploitScenario != "" {
		fmt.Fprintf(&b, "**Exploit Scenario:**\n%s\n\n", f.ExploitScenario)
	}
	if f.Recommendation != "" {
		fmt.Fprintf(&b, "**Recommendation:**\n%s\n", f.Recommendation)
	}
	return b.String()
}

// PostReview posts all findings as a PR review with inline comments.
// Checks for existing Barry reviews first to avoid duplicates.
func PostReview(ctx context.Context, client Reviewer, prNumber int, commitID string, findingsList []findings.Finding, log *slog.Logger) error {

	if len(findingsList) == 0 {
		log.Info("No findings to post")
		return nil
	}

	// Check for existing review.
	exists, err := client.HasExistingReview(ctx, prNumber)
	if err != nil {
		log.Warn("Failed to check for existing review", "error", err)
		// Continue — better to have a duplicate than to miss findings.
	}
	if exists {
		log.Info("Barry review already exists on this PR, skipping")
		return nil
	}

	// Build review comments.
	var comments []gh.ReviewComment
	for _, f := range findingsList {
		if f.File == "" || f.Line == 0 {
			continue
		}
		comments = append(comments, gh.ReviewComment{
			Path: f.File,
			Line: f.Line,
			Body: FormatFindingComment(&f),
		})
	}

	if len(comments) == 0 {
		log.Info("No comments with valid file/line positions to post")
		return nil
	}

	log.Info("Posting review comments", "count", len(comments))
	return client.PostReviewComments(ctx, prNumber, commitID, comments)
}

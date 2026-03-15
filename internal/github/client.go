package github

import (
	"context"
	"fmt"
	"strings"

	gh "github.com/google/go-github/v68/github"
)

// Client wraps the GitHub API for PR operations.
type Client struct {
	client *gh.Client
	owner  string
	repo   string
}

// NewClient creates a GitHub API client authenticated with the given token.
func NewClient(token, owner, repo string) *Client {
	return &Client{
		client: gh.NewClient(nil).WithAuthToken(token),
		owner:  owner,
		repo:   repo,
	}
}

// NewClientWithGH creates a Client wrapping an existing go-github client.
func NewClientWithGH(ghClient *gh.Client, owner, repo string) *Client {
	return &Client{
		client: ghClient,
		owner:  owner,
		repo:   repo,
	}
}

// GetPRData fetches PR metadata and the list of changed files.
func (c *Client) GetPRData(ctx context.Context, prNumber int) (*PRData, error) {
	pr, _, err := c.client.PullRequests.Get(ctx, c.owner, c.repo, prNumber)
	if err != nil {
		return nil, fmt.Errorf("fetching PR: %w", err)
	}

	files, _, err := c.client.PullRequests.ListFiles(ctx, c.owner, c.repo, prNumber, &gh.ListOptions{PerPage: 300})
	if err != nil {
		return nil, fmt.Errorf("listing PR files: %w", err)
	}

	data := &PRData{
		Number:       pr.GetNumber(),
		Title:        pr.GetTitle(),
		Body:         pr.GetBody(),
		Author:       pr.GetUser().GetLogin(),
		HeadSHA:      pr.GetHead().GetSHA(),
		RepoFullName: pr.GetHead().GetRepo().GetFullName(),
		Additions:    pr.GetAdditions(),
		Deletions:    pr.GetDeletions(),
		ChangedFiles: pr.GetChangedFiles(),
	}

	for _, f := range files {
		data.Files = append(data.Files, PRFile{
			Filename:  f.GetFilename(),
			Status:    f.GetStatus(),
			Additions: f.GetAdditions(),
			Deletions: f.GetDeletions(),
			Patch:     f.GetPatch(),
		})
	}

	return data, nil
}

// GetPRDiff fetches the unified diff for the entire PR.
func (c *Client) GetPRDiff(ctx context.Context, prNumber int) (string, error) {
	diff, _, err := c.client.PullRequests.GetRaw(
		ctx, c.owner, c.repo, prNumber,
		gh.RawOptions{Type: gh.Diff},
	)
	if err != nil {
		return "", fmt.Errorf("fetching PR diff: %w", err)
	}
	return diff, nil
}

// PostReviewComments creates a PR review with inline comments.
// Falls back to individual comments if the batch review fails.
func (c *Client) PostReviewComments(ctx context.Context, prNumber int, commitID string, comments []ReviewComment) error {
	if len(comments) == 0 {
		return nil
	}

	// Build review comments for batch submission.
	var reviewComments []*gh.DraftReviewComment
	for _, rc := range comments {
		reviewComments = append(reviewComments, &gh.DraftReviewComment{
			Path: gh.Ptr(rc.Path),
			Line: gh.Ptr(rc.Line),
			Side: gh.Ptr("RIGHT"),
			Body: gh.Ptr(rc.Body),
		})
	}

	review := &gh.PullRequestReviewRequest{
		CommitID: gh.Ptr(commitID),
		Event:    gh.Ptr("COMMENT"),
		Body:     gh.Ptr("🤖 Barry Security Review"),
		Comments: reviewComments,
	}

	_, _, err := c.client.PullRequests.CreateReview(ctx, c.owner, c.repo, prNumber, review)
	if err == nil {
		return nil
	}

	// Batch failed — fall back to individual comments.
	var firstErr error
	for _, rc := range comments {
		comment := &gh.PullRequestComment{
			CommitID: gh.Ptr(commitID),
			Path:     gh.Ptr(rc.Path),
			Line:     gh.Ptr(rc.Line),
			Side:     gh.Ptr("RIGHT"),
			Body:     gh.Ptr(rc.Body),
		}
		_, _, cerr := c.client.PullRequests.CreateComment(ctx, c.owner, c.repo, prNumber, comment)
		if cerr != nil && firstErr == nil {
			firstErr = cerr
		}
	}
	return firstErr
}

// HasExistingReview checks whether the bot has already posted a review on this PR.
func (c *Client) HasExistingReview(ctx context.Context, prNumber int) (bool, error) {
	reviews, _, err := c.client.PullRequests.ListReviews(ctx, c.owner, c.repo, prNumber, &gh.ListOptions{PerPage: 100})
	if err != nil {
		return false, fmt.Errorf("listing reviews: %w", err)
	}
	for _, r := range reviews {
		if strings.Contains(r.GetBody(), "Barry Security Review") {
			return true, nil
		}
	}
	return false, nil
}

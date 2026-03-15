package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gh "github.com/google/go-github/v68/github"
)

// testClient creates a Client pointing at a httptest server.
func testClient(t *testing.T, mux *http.ServeMux) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	httpClient := srv.Client()
	ghClient := gh.NewClient(httpClient).WithAuthToken("test-token")
	ghClient.BaseURL, _ = ghClient.BaseURL.Parse(srv.URL + "/")
	return NewClientWithGH(ghClient, "owner", "repo"), srv
}

func TestNewClient(t *testing.T) {
	c := NewClient("tok", "o", "r")
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
}

func TestGetPRData_HappyPath(t *testing.T) {
	mux := http.NewServeMux()

	pr := &gh.PullRequest{
		Number:       gh.Ptr(42),
		Title:        gh.Ptr("fix bug"),
		Body:         gh.Ptr("description"),
		User:         &gh.User{Login: gh.Ptr("dev")},
		Head:         &gh.PullRequestBranch{SHA: gh.Ptr("abc"), Repo: &gh.Repository{FullName: gh.Ptr("owner/repo")}},
		Additions:    gh.Ptr(10),
		Deletions:    gh.Ptr(5),
		ChangedFiles: gh.Ptr(2),
	}

	mux.HandleFunc("/repos/owner/repo/pulls/42", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pr)
	})

	files := []*gh.CommitFile{
		{Filename: gh.Ptr("a.go"), Status: gh.Ptr("modified"), Additions: gh.Ptr(5), Deletions: gh.Ptr(2), Patch: gh.Ptr("@@ -1 +1 @@")},
	}
	mux.HandleFunc("/repos/owner/repo/pulls/42/files", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(files)
	})

	c, _ := testClient(t, mux)
	data, err := c.GetPRData(context.Background(), 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Number != 42 {
		t.Errorf("Number = %d, want 42", data.Number)
	}
	if data.Title != "fix bug" {
		t.Errorf("Title = %q, want 'fix bug'", data.Title)
	}
	if len(data.Files) != 1 {
		t.Fatalf("Files count = %d, want 1", len(data.Files))
	}
	if data.Files[0].Filename != "a.go" {
		t.Errorf("Filename = %q, want 'a.go'", data.Files[0].Filename)
	}
}

func TestGetPRData_APIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	c, _ := testClient(t, mux)
	_, err := c.GetPRData(context.Background(), 1)
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestGetPRDiff_HappyPath(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept"), "diff") {
			_, _ = w.Write([]byte("diff --git a/file.go b/file.go\n"))
			return
		}
		w.WriteHeader(http.StatusNotAcceptable)
	})

	c, _ := testClient(t, mux)
	diff, err := c.GetPRDiff(context.Background(), 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(diff, "diff --git") {
		t.Errorf("diff = %q, want diff content", diff)
	}
}

func TestGetPRDiff_APIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	c, _ := testClient(t, mux)
	_, err := c.GetPRDiff(context.Background(), 1)
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestPostReviewComments_EmptyComments(t *testing.T) {
	c := NewClient("tok", "o", "r")
	err := c.PostReviewComments(context.Background(), 1, "sha", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPostReviewComments_BatchSucceeds(t *testing.T) {
	mux := http.NewServeMux()
	var calledReview bool
	mux.HandleFunc("/repos/owner/repo/pulls/1/reviews", func(w http.ResponseWriter, r *http.Request) {
		calledReview = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&gh.PullRequestReview{ID: gh.Ptr(int64(1))})
	})

	c, _ := testClient(t, mux)
	comments := []ReviewComment{{Path: "a.go", Line: 5, Body: "test"}}
	err := c.PostReviewComments(context.Background(), 1, "sha", comments)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !calledReview {
		t.Error("should have called create review endpoint")
	}
}

func TestPostReviewComments_FallbackToIndividual(t *testing.T) {
	mux := http.NewServeMux()
	var individualCount int
	mux.HandleFunc("/repos/owner/repo/pulls/1/reviews", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Validation Failed"}`))
	})
	mux.HandleFunc("/repos/owner/repo/pulls/1/comments", func(w http.ResponseWriter, _ *http.Request) {
		individualCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&gh.PullRequestComment{ID: gh.Ptr(int64(1))})
	})

	c, _ := testClient(t, mux)
	comments := []ReviewComment{
		{Path: "a.go", Line: 5, Body: "issue1"},
		{Path: "b.go", Line: 10, Body: "issue2"},
	}
	err := c.PostReviewComments(context.Background(), 1, "sha", comments)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if individualCount != 2 {
		t.Errorf("individual comment calls = %d, want 2", individualCount)
	}
}

func TestHasExistingReview_NoBarryReview(t *testing.T) {
	mux := http.NewServeMux()
	reviews := []*gh.PullRequestReview{
		{Body: gh.Ptr("LGTM")},
		{Body: gh.Ptr("Needs work")},
	}
	mux.HandleFunc("/repos/owner/repo/pulls/1/reviews", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reviews)
	})

	c, _ := testClient(t, mux)
	exists, err := c.HasExistingReview(context.Background(), 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("should return false when no Barry review exists")
	}
}

func TestHasExistingReview_BarryReviewExists(t *testing.T) {
	mux := http.NewServeMux()
	reviews := []*gh.PullRequestReview{
		{Body: gh.Ptr("🤖 Barry Security Review")},
	}
	mux.HandleFunc("/repos/owner/repo/pulls/1/reviews", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reviews)
	})

	c, _ := testClient(t, mux)
	exists, err := c.HasExistingReview(context.Background(), 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("should return true when Barry review exists")
	}
}

func TestNewClientWithGH(t *testing.T) {
	ghClient := gh.NewClient(nil).WithAuthToken("test")
	c := NewClientWithGH(ghClient, "o", "r")
	if c == nil {
		t.Fatal("NewClientWithGH returned nil")
	}
}

func TestGetPRData_ListFilesError(t *testing.T) {
	mux := http.NewServeMux()
	pr := &gh.PullRequest{
		Number: gh.Ptr(1),
		Title:  gh.Ptr("test"),
		User:   &gh.User{Login: gh.Ptr("dev")},
		Head:   &gh.PullRequestBranch{SHA: gh.Ptr("abc"), Repo: &gh.Repository{FullName: gh.Ptr("owner/repo")}},
	}
	mux.HandleFunc("/repos/owner/repo/pulls/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pr)
	})
	mux.HandleFunc("/repos/owner/repo/pulls/1/files", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c, _ := testClient(t, mux)
	_, err := c.GetPRData(context.Background(), 1)
	if err == nil || !strings.Contains(err.Error(), "listing PR files") {
		t.Fatalf("expected listing files error, got: %v", err)
	}
}

func TestHasExistingReview_APIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1/reviews", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c, _ := testClient(t, mux)
	_, err := c.HasExistingReview(context.Background(), 1)
	if err == nil {
		t.Fatal("expected error for API failure")
	}
}

func TestPostReviewComments_FallbackIndividualError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1/reviews", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Validation Failed"}`))
	})
	mux.HandleFunc("/repos/owner/repo/pulls/1/comments", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c, _ := testClient(t, mux)
	comments := []ReviewComment{{Path: "a.go", Line: 5, Body: "issue"}}
	err := c.PostReviewComments(context.Background(), 1, "sha", comments)
	if err == nil {
		t.Fatal("expected error when individual comment fails")
	}
}

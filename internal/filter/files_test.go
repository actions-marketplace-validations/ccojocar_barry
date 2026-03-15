package filter

import (
	"testing"

	gh "github.com/cosmin/barry/internal/github"
)

func TestShouldExcludeFile(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		excludeDirs []string
		want        bool
	}{
		// Generated/vendored paths
		{name: "vendor dir", filename: "vendor/lib/foo.go", want: true},
		{name: "node_modules", filename: "node_modules/pkg/index.js", want: true},
		{name: "go.sum", filename: "go.sum", want: true},
		{name: "package-lock.json", filename: "package-lock.json", want: true},
		{name: "yarn.lock", filename: "yarn.lock", want: true},
		{name: "Pipfile.lock", filename: "Pipfile.lock", want: true},
		{name: "poetry.lock", filename: "poetry.lock", want: true},
		{name: "pnpm-lock.yaml", filename: "pnpm-lock.yaml", want: true},

		// Non-code asset files
		{name: "png image", filename: "assets/logo.png", want: true},
		{name: "jpg image", filename: "photos/pic.jpg", want: true},
		{name: "pdf file", filename: "docs/report.pdf", want: true},
		{name: "zip archive", filename: "dist/release.zip", want: true},
		{name: "font file", filename: "fonts/inter.woff2", want: true},

		// User-excluded directories
		{name: "excluded dir", filename: "test/fixtures/data.go", excludeDirs: []string{"test/fixtures"}, want: true},
		{name: "excluded dir with slash", filename: "build/out.js", excludeDirs: []string{"build/"}, want: true},

		// Files that should NOT be excluded
		{name: "go source", filename: "main.go", want: false},
		{name: "python source", filename: "app.py", want: false},
		{name: "js source", filename: "src/index.js", want: false},
		{name: "typescript", filename: "src/app.ts", want: false},
		{name: "markdown", filename: "README.md", want: false},
		{name: "dockerfile", filename: "Dockerfile", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldExcludeFile(tt.filename, tt.excludeDirs)
			if got != tt.want {
				t.Errorf("ShouldExcludeFile(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestFilterPRFiles(t *testing.T) {
	files := []gh.PRFile{
		{Filename: "main.go"},
		{Filename: "vendor/lib/x.go"},
		{Filename: "src/app.ts"},
		{Filename: "assets/logo.png"},
		{Filename: "go.sum"},
	}

	got := FilterPRFiles(files, nil)
	if len(got) != 2 {
		t.Fatalf("FilterPRFiles returned %d files, want 2", len(got))
	}
	if got[0].Filename != "main.go" {
		t.Errorf("got[0] = %q, want main.go", got[0].Filename)
	}
	if got[1].Filename != "src/app.ts" {
		t.Errorf("got[1] = %q, want src/app.ts", got[1].Filename)
	}
}

func TestFilterPRFilesWithExcludeDirs(t *testing.T) {
	files := []gh.PRFile{
		{Filename: "main.go"},
		{Filename: "test/fixtures/data.json"},
		{Filename: "src/app.go"},
	}

	got := FilterPRFiles(files, []string{"test/fixtures"})
	if len(got) != 2 {
		t.Fatalf("FilterPRFiles returned %d files, want 2", len(got))
	}
}

func TestFilterPRFilesEmpty(t *testing.T) {
	got := FilterPRFiles(nil, nil)
	if got != nil {
		t.Errorf("FilterPRFiles(nil) = %v, want nil", got)
	}
}

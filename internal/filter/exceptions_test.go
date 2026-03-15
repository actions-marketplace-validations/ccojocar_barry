package filter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cosmin/barry/internal/findings"
)

func TestMatchException(t *testing.T) {
	tests := []struct {
		name       string
		finding    findings.Finding
		exceptions []Exception
		want       string
	}{
		{
			name:       "no exceptions",
			finding:    findings.Finding{File: "src/db.go", Category: "sql_injection"},
			exceptions: nil,
			want:       "",
		},
		{
			name:    "exact file match",
			finding: findings.Finding{File: "src/db.go", Category: "sql_injection"},
			exceptions: []Exception{
				{File: "src/db.go", Reason: "known safe"},
			},
			want: "known safe",
		},
		{
			name:    "glob file match",
			finding: findings.Finding{File: "vendor/lib.go", Category: "xss"},
			exceptions: []Exception{
				{File: "vendor/*.go", Reason: "third-party"},
			},
			want: "third-party",
		},
		{
			name:    "category only match",
			finding: findings.Finding{File: "src/api.go", Category: "open_redirect"},
			exceptions: []Exception{
				{Category: "open_redirect", Reason: "handled at proxy"},
			},
			want: "handled at proxy",
		},
		{
			name:    "category case insensitive",
			finding: findings.Finding{File: "src/api.go", Category: "SQL_Injection"},
			exceptions: []Exception{
				{Category: "sql_injection", Reason: "case test"},
			},
			want: "case test",
		},
		{
			name:    "file+category both match",
			finding: findings.Finding{File: "src/db.go", Category: "sql_injection"},
			exceptions: []Exception{
				{File: "src/db.go", Category: "sql_injection", Reason: "parameterized"},
			},
			want: "parameterized",
		},
		{
			name:    "file matches but category does not",
			finding: findings.Finding{File: "src/db.go", Category: "xss"},
			exceptions: []Exception{
				{File: "src/db.go", Category: "sql_injection", Reason: "nope"},
			},
			want: "",
		},
		{
			name:    "category matches but file does not",
			finding: findings.Finding{File: "src/api.go", Category: "sql_injection"},
			exceptions: []Exception{
				{File: "src/db.go", Category: "sql_injection", Reason: "nope"},
			},
			want: "",
		},
		{
			name:    "multiple exceptions first wins",
			finding: findings.Finding{File: "src/db.go", Category: "sql_injection"},
			exceptions: []Exception{
				{Category: "xss", Reason: "not this one"},
				{File: "src/db.go", Reason: "file match"},
				{Category: "sql_injection", Reason: "cat match"},
			},
			want: "file match",
		},
		{
			name:    "default reason file+category",
			finding: findings.Finding{File: "src/db.go", Category: "sql_injection"},
			exceptions: []Exception{
				{File: "src/db.go", Category: "sql_injection"},
			},
			want: `excluded by exception: file="src/db.go" category="sql_injection"`,
		},
		{
			name:    "default reason file only",
			finding: findings.Finding{File: "src/db.go", Category: "sql_injection"},
			exceptions: []Exception{
				{File: "src/db.go"},
			},
			want: `excluded by exception: file="src/db.go"`,
		},
		{
			name:    "default reason category only",
			finding: findings.Finding{File: "src/db.go", Category: "sql_injection"},
			exceptions: []Exception{
				{Category: "sql_injection"},
			},
			want: `excluded by exception: category="sql_injection"`,
		},
		{
			name:    "no match at all",
			finding: findings.Finding{File: "src/handler.go", Category: "command_injection"},
			exceptions: []Exception{
				{File: "src/db.go", Reason: "wrong file"},
				{Category: "xss", Reason: "wrong category"},
			},
			want: "",
		},
		// --- Line-based matching ---
		{
			name:    "line only match",
			finding: findings.Finding{File: "src/db.go", Line: 42, Category: "sql_injection"},
			exceptions: []Exception{
				{Line: 42, Reason: "known safe line"},
			},
			want: "known safe line",
		},
		{
			name:    "line mismatch",
			finding: findings.Finding{File: "src/db.go", Line: 42, Category: "sql_injection"},
			exceptions: []Exception{
				{Line: 99, Reason: "wrong line"},
			},
			want: "",
		},
		{
			name:    "file+line match",
			finding: findings.Finding{File: "src/db.go", Line: 42, Category: "sql_injection"},
			exceptions: []Exception{
				{File: "src/db.go", Line: 42, Reason: "exact location"},
			},
			want: "exact location",
		},
		{
			name:    "file+line+category match",
			finding: findings.Finding{File: "src/db.go", Line: 42, Category: "sql_injection"},
			exceptions: []Exception{
				{File: "src/db.go", Line: 42, Category: "sql_injection", Reason: "fully pinned"},
			},
			want: "fully pinned",
		},
		{
			name:    "file+line match but category mismatch",
			finding: findings.Finding{File: "src/db.go", Line: 42, Category: "xss"},
			exceptions: []Exception{
				{File: "src/db.go", Line: 42, Category: "sql_injection", Reason: "nope"},
			},
			want: "",
		},
		{
			name:    "line zero means any line",
			finding: findings.Finding{File: "src/db.go", Line: 999, Category: "sql_injection"},
			exceptions: []Exception{
				{File: "src/db.go", Category: "sql_injection", Reason: "all lines"},
			},
			want: "all lines",
		},
		{
			name:    "default reason with line",
			finding: findings.Finding{File: "src/db.go", Line: 42, Category: "sql_injection"},
			exceptions: []Exception{
				{File: "src/db.go", Line: 42},
			},
			want: `excluded by exception: file="src/db.go" line=42`,
		},
		{
			name:    "default reason line only",
			finding: findings.Finding{File: "src/db.go", Line: 42, Category: "sql_injection"},
			exceptions: []Exception{
				{Line: 42},
			},
			want: `excluded by exception: line=42`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchException(&tt.finding, tt.exceptions)
			if got != tt.want {
				t.Errorf("MatchException() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadExceptions(t *testing.T) {
	t.Run("valid file", func(t *testing.T) {
		content := `{
			"exceptions": [
				{"file": "src/db.go", "category": "sql_injection", "reason": "safe"},
				{"category": "open_redirect", "reason": "proxy handles it"}
			]
		}`
		path := writeTemp(t, content)
		exceptions, err := LoadExceptions(path)
		if err != nil {
			t.Fatalf("LoadExceptions() error: %v", err)
		}
		if len(exceptions) != 2 {
			t.Fatalf("got %d exceptions, want 2", len(exceptions))
		}
		if exceptions[0].File != "src/db.go" {
			t.Errorf("exceptions[0].File = %q, want src/db.go", exceptions[0].File)
		}
		if exceptions[1].Category != "open_redirect" {
			t.Errorf("exceptions[1].Category = %q, want open_redirect", exceptions[1].Category)
		}
	})

	t.Run("empty exceptions array", func(t *testing.T) {
		path := writeTemp(t, `{"exceptions": []}`)
		exceptions, err := LoadExceptions(path)
		if err != nil {
			t.Fatalf("LoadExceptions() error: %v", err)
		}
		if len(exceptions) != 0 {
			t.Errorf("got %d exceptions, want 0", len(exceptions))
		}
	})

	t.Run("valid file with lines", func(t *testing.T) {
		content := `{
			"exceptions": [
				{"file": "src/db.go", "line": 42, "category": "sql_injection", "reason": "safe"},
				{"file": "src/db.go", "line": 100}
			]
		}`
		path := writeTemp(t, content)
		exceptions, err := LoadExceptions(path)
		if err != nil {
			t.Fatalf("LoadExceptions() error: %v", err)
		}
		if len(exceptions) != 2 {
			t.Fatalf("got %d exceptions, want 2", len(exceptions))
		}
		if exceptions[0].Line != 42 {
			t.Errorf("exceptions[0].Line = %d, want 42", exceptions[0].Line)
		}
		if exceptions[1].Line != 100 {
			t.Errorf("exceptions[1].Line = %d, want 100", exceptions[1].Line)
		}
	})

	t.Run("missing file and category and line", func(t *testing.T) {
		path := writeTemp(t, `{"exceptions": [{"reason": "no match criteria"}]}`)
		_, err := LoadExceptions(path)
		if err == nil {
			t.Fatal("expected error for exception with no match criteria")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		path := writeTemp(t, `not json`)
		_, err := LoadExceptions(path)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := LoadExceptions(filepath.Join(t.TempDir(), "nonexistent.json"))
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exceptions.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

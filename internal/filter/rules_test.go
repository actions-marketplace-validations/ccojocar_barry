package filter

import (
	"testing"

	"github.com/cosmin/barry/internal/findings"
)

func TestGetExclusionReason(t *testing.T) {
	tests := []struct {
		name    string
		finding findings.Finding
		want    string // empty means not excluded
	}{
		// --- Markdown files ---
		{
			name:    "markdown file excluded",
			finding: findings.Finding{File: "README.md", Description: "SQL injection vulnerability"},
			want:    "Finding in Markdown documentation file",
		},
		{
			name:    "markdown uppercase excluded",
			finding: findings.Finding{File: "docs/GUIDE.MD", Description: "command injection"},
			want:    "Finding in Markdown documentation file",
		},

		// --- DOS patterns ---
		{
			name:    "denial of service excluded",
			finding: findings.Finding{File: "app.py", Description: "Denial of Service vulnerability via unbounded input"},
			want:    "Generic DOS/resource exhaustion finding (low signal)",
		},
		{
			name:    "resource exhaustion excluded",
			finding: findings.Finding{File: "server.go", Description: "Resource exhaustion through memory allocation"},
			want:    "Generic DOS/resource exhaustion finding (low signal)",
		},
		{
			name:    "infinite loop excluded",
			finding: findings.Finding{File: "lib.js", Description: "Infinite recursion could crash the server"},
			want:    "Generic DOS/resource exhaustion finding (low signal)",
		},

		// --- Rate limiting patterns ---
		{
			name:    "missing rate limit excluded",
			finding: findings.Finding{File: "api.go", Description: "Missing rate limit on login endpoint"},
			want:    "Generic rate limiting recommendation",
		},
		{
			name:    "implement rate limit excluded",
			finding: findings.Finding{File: "handler.py", Description: "Implement rate limiting to prevent abuse"},
			want:    "Generic rate limiting recommendation",
		},

		// --- Resource patterns ---
		{
			name:    "memory leak excluded",
			finding: findings.Finding{File: "conn.go", Description: "Potential memory leak in connection handler"},
			want:    "Resource management finding (not a security vulnerability)",
		},
		{
			name:    "unclosed connection excluded",
			finding: findings.Finding{File: "db.py", Description: "Unclosed connection in database module"},
			want:    "Resource management finding (not a security vulnerability)",
		},

		// --- Open redirect patterns ---
		{
			name:    "open redirect excluded",
			finding: findings.Finding{File: "auth.go", Description: "Open redirect vulnerability in login callback"},
			want:    "Open redirect vulnerability (not high impact)",
		},

		// --- Regex injection patterns ---
		{
			name:    "regex injection excluded",
			finding: findings.Finding{File: "search.py", Description: "Regex injection in search endpoint"},
			want:    "Regex injection finding (not applicable)",
		},
		{
			name:    "regex DOS excluded",
			finding: findings.Finding{File: "parser.js", Description: "Regular expression flooding attack"},
			want:    "Regex injection finding (not applicable)",
		},

		// --- Memory safety in non-C/C++ ---
		{
			name:    "buffer overflow in Python excluded",
			finding: findings.Finding{File: "utils.py", Description: "Buffer overflow in string processing"},
			want:    "Memory safety finding in non-C/C++ code (not applicable)",
		},
		{
			name:    "use after free in Go excluded",
			finding: findings.Finding{File: "handler.go", Description: "Use-after-free vulnerability"},
			want:    "Memory safety finding in non-C/C++ code (not applicable)",
		},
		{
			name:    "buffer overflow in C NOT excluded",
			finding: findings.Finding{File: "core.c", Description: "Buffer overflow in string processing"},
			want:    "", // should NOT be excluded — valid finding in C
		},
		{
			name:    "buffer overflow in C++ NOT excluded",
			finding: findings.Finding{File: "engine.cpp", Description: "Heap overflow in parser"},
			want:    "", // should NOT be excluded — valid finding in C++
		},
		{
			name:    "buffer overflow in header NOT excluded",
			finding: findings.Finding{File: "defs.h", Description: "Integer overflow in macro"},
			want:    "", // should NOT be excluded — valid finding in C header
		},

		// --- SSRF in HTML ---
		{
			name:    "ssrf in HTML excluded",
			finding: findings.Finding{File: "index.html", Description: "SSRF vulnerability in form action"},
			want:    "SSRF finding in HTML file (not applicable to client-side code)",
		},
		{
			name:    "ssrf in Python NOT excluded",
			finding: findings.Finding{File: "api.py", Description: "Server-side request forgery in API endpoint"},
			want:    "", // should NOT be excluded — valid finding in server code
		},

		// --- True positives (should NOT be excluded) ---
		{
			name:    "SQL injection not excluded",
			finding: findings.Finding{File: "db.py", Description: "SQL injection vulnerability in user query"},
			want:    "",
		},
		{
			name:    "XSS not excluded",
			finding: findings.Finding{File: "template.js", Description: "Cross-site scripting in template rendering"},
			want:    "",
		},
		{
			name:    "command injection not excluded",
			finding: findings.Finding{File: "exec.go", Description: "Command injection via user-controlled input"},
			want:    "",
		},
		{
			name:    "path traversal not excluded",
			finding: findings.Finding{File: "files.py", Description: "Path traversal allows reading arbitrary files"},
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetExclusionReason(&tt.finding)
			if got != tt.want {
				t.Errorf("GetExclusionReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

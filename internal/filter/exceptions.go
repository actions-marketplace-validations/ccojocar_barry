package filter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cosmin/barry/internal/findings"
)

// Exception defines a single exclusion rule. A finding is excluded when all
// non-empty fields match. At least one of File, Category, or Line must be set.
//
//   - File: a glob pattern matched against the finding's file path (filepath.Match).
//   - Line: exact line number match (0 means "any line").
//   - Category: matched case-insensitively against the finding's category.
//   - Reason: human-readable justification (used in logs and excluded output).
type Exception struct {
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Category string `json:"category,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// exceptionsFile is the on-disk JSON format: {"exceptions": [...]}.
type exceptionsFile struct {
	Exceptions []Exception `json:"exceptions"`
}

// LoadExceptions reads and parses a JSON exceptions file. The file must contain
// a top-level "exceptions" array. Returns an error if any entry has neither
// file nor category set.
func LoadExceptions(path string) ([]Exception, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading exceptions file: %w", err)
	}

	var ef exceptionsFile
	if err := json.Unmarshal(data, &ef); err != nil {
		return nil, fmt.Errorf("parsing exceptions file: %w", err)
	}

	for i, e := range ef.Exceptions {
		if e.File == "" && e.Category == "" && e.Line == 0 {
			return nil, fmt.Errorf("exception %d: at least one of 'file', 'line', or 'category' must be set", i)
		}
	}

	return ef.Exceptions, nil
}

// MatchException checks whether a finding matches any exception in the list.
// Returns the reason string of the first matching exception, or "" if none match.
func MatchException(f *findings.Finding, exceptions []Exception) string {
	for _, e := range exceptions {
		if matchesSingle(f, &e) {
			reason := e.Reason
			if reason == "" {
				reason = buildDefaultReason(&e)
			}
			return reason
		}
	}
	return ""
}

// matchesSingle returns true when every non-empty field in the exception matches
// the finding. Fields are ANDed together.
func matchesSingle(f *findings.Finding, e *Exception) bool {
	if e.File != "" {
		matched, err := filepath.Match(e.File, f.File)
		if err != nil || !matched {
			return false
		}
	}
	if e.Line != 0 {
		if f.Line != e.Line {
			return false
		}
	}
	if e.Category != "" {
		if !strings.EqualFold(e.Category, f.Category) {
			return false
		}
	}
	return true
}

func buildDefaultReason(e *Exception) string {
	var parts []string
	if e.File != "" {
		parts = append(parts, fmt.Sprintf("file=%q", e.File))
	}
	if e.Line != 0 {
		parts = append(parts, fmt.Sprintf("line=%d", e.Line))
	}
	if e.Category != "" {
		parts = append(parts, fmt.Sprintf("category=%q", e.Category))
	}
	return "excluded by exception: " + strings.Join(parts, " ")
}

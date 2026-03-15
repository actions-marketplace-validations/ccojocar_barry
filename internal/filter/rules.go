package filter

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cosmin/barry/internal/findings"
)

// rule pairs a set of compiled patterns with a human-readable exclusion reason.
type rule struct {
	patterns []*regexp.Regexp
	reason   string
}

// fileRule is a rule that applies only when the file extension matches.
type fileRule struct {
	rule
	// matchExts: if non-empty, only apply when the file extension is in this set.
	matchExts map[string]bool
	// invertExts: if true, apply when the extension is NOT in matchExts.
	invertExts bool
}

// compile is a shorthand for regexp.MustCompile with case-insensitive flag.
func compile(pattern string) *regexp.Regexp {
	return regexp.MustCompile("(?i)" + pattern)
}

var dosPatterns = rule{
	patterns: []*regexp.Regexp{
		compile(`\b(denial of service|dos attack|resource exhaustion)\b`),
		compile(`\b(exhaust|overwhelm|overload).*?(resource|memory|cpu)\b`),
		compile(`\b(infinite|unbounded).*?(loop|recursion)\b`),
	},
	reason: "Generic DOS/resource exhaustion finding (low signal)",
}

var rateLimitingPatterns = rule{
	patterns: []*regexp.Regexp{
		compile(`\b(missing|lack of|no)\s+rate\s+limit`),
		compile(`\brate\s+limiting\s+(missing|required|not implemented)`),
		compile(`\b(implement|add)\s+rate\s+limit`),
		compile(`\bunlimited\s+(requests|calls|api)`),
	},
	reason: "Generic rate limiting recommendation",
}

var resourcePatterns = rule{
	patterns: []*regexp.Regexp{
		compile(`\b(resource|memory|file)\s+leak\s+potential`),
		compile(`\bunclosed\s+(resource|file|connection)`),
		compile(`\b(close|cleanup|release)\s+(resource|file|connection)`),
		compile(`\bpotential\s+memory\s+leak`),
		compile(`\b(database|thread|socket|connection)\s+leak`),
	},
	reason: "Resource management finding (not a security vulnerability)",
}

var openRedirectPatterns = rule{
	patterns: []*regexp.Regexp{
		compile(`\b(open redirect|unvalidated redirect)\b`),
		compile(`\b(redirect.(attack|exploit|vulnerability))\b`),
		compile(`\b(malicious.redirect)\b`),
	},
	reason: "Open redirect vulnerability (not high impact)",
}

var regexInjectionPatterns = rule{
	patterns: []*regexp.Regexp{
		compile(`\b(regex|regular expression)\s+injection\b`),
		compile(`\b(regex|regular expression)\s+denial of service\b`),
		compile(`\b(regex|regular expression)\s+flooding\b`),
	},
	reason: "Regex injection finding (not applicable)",
}

var memorySafetyPatterns = fileRule{
	rule: rule{
		patterns: []*regexp.Regexp{
			compile(`\b(buffer overflow|stack overflow|heap overflow)\b`),
			compile(`\b(oob)\s+(read|write|access)\b`),
			compile(`\b(out.?of.?bounds?)\b`),
			compile(`\b(memory safety|memory corruption)\b`),
			compile(`\b(use.?after.?free|double.?free|null.?pointer.?dereference)\b`),
			compile(`\b(segmentation fault|segfault|memory violation)\b`),
			compile(`\b(bounds check|boundary check|array bounds)\b`),
			compile(`\b(integer overflow|integer underflow|integer conversion)\b`),
			compile(`\barbitrary.?(memory read|pointer dereference|memory address|memory pointer)\b`),
		},
		reason: "Memory safety finding in non-C/C++ code (not applicable)",
	},
	matchExts:  map[string]bool{".c": true, ".cc": true, ".cpp": true, ".h": true},
	invertExts: true, // exclude when NOT C/C++
}

var ssrfPatterns = fileRule{
	rule: rule{
		patterns: []*regexp.Regexp{
			compile(`\b(ssrf|server\s*-?\s*side\s*-?\s*request\s*-?\s*forgery)\b`),
		},
		reason: "SSRF finding in HTML file (not applicable to client-side code)",
	},
	matchExts:  map[string]bool{".html": true},
	invertExts: false, // apply only when IS .html
}

// allTextRules are rules that match against the combined description+title text
// and are not file-extension dependent.
var allTextRules = []rule{
	dosPatterns,
	rateLimitingPatterns,
	resourcePatterns,
	openRedirectPatterns,
	regexInjectionPatterns,
}

// allFileRules are rules that additionally depend on the file extension.
var allFileRules = []fileRule{
	memorySafetyPatterns,
	ssrfPatterns,
}

// GetExclusionReason checks whether a finding matches any hard exclusion rule.
// Returns the exclusion reason string, or "" if the finding is not excluded.
func GetExclusionReason(f *findings.Finding) string {
	filePath := f.File
	if strings.ToLower(filepath.Ext(filePath)) == ".md" {
		return "Finding in Markdown documentation file"
	}

	combined := strings.ToLower(f.Description)

	// Text-only rules.
	for _, r := range allTextRules {
		for _, p := range r.patterns {
			if p.MatchString(combined) {
				return r.reason
			}
		}
	}

	// File-extension-dependent rules.
	ext := strings.ToLower(filepath.Ext(filePath))
	for _, fr := range allFileRules {
		applies := false
		if fr.invertExts {
			// Rule applies when the extension is NOT in matchExts.
			applies = !fr.matchExts[ext]
		} else {
			// Rule applies only when the extension IS in matchExts.
			applies = fr.matchExts[ext]
		}
		if !applies {
			continue
		}
		for _, p := range fr.patterns {
			if p.MatchString(combined) {
				return fr.reason
			}
		}
	}

	return ""
}

package filter

import (
	"path/filepath"
	"strings"

	gh "github.com/cosmin/barry/internal/github"
)

// generatedPaths lists path substrings that indicate generated/vendored files.
// All entries must be lowercase for case-insensitive matching.
var generatedPaths = []string{
	"vendor/", "node_modules/", "package-lock.json", "yarn.lock",
	"go.sum", "pipfile.lock", "poetry.lock", "pnpm-lock.yaml",
}

// nonCodeExts lists file extensions for binary/non-code assets.
var nonCodeExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".svg": true, ".ico": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".pdf": true, ".zip": true,
}

// FilterPRFiles removes files that should be excluded from analysis.
func FilterPRFiles(files []gh.PRFile, excludeDirs []string) []gh.PRFile {
	var filtered []gh.PRFile
	for _, f := range files {
		if ShouldExcludeFile(f.Filename, excludeDirs) {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// ShouldExcludeFile returns true if the file should be excluded from scanning.
func ShouldExcludeFile(filename string, excludeDirs []string) bool {
	lower := strings.ToLower(filename)
	for _, p := range generatedPaths {
		if strings.Contains(lower, p) {
			return true
		}
	}

	for _, dir := range excludeDirs {
		dir = strings.TrimSuffix(dir, "/")
		if strings.HasPrefix(filename, dir+"/") {
			return true
		}
	}

	ext := strings.ToLower(filepath.Ext(filename))
	return nonCodeExts[ext]
}

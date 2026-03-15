package agents

// State keys used across agents for reading/writing session state.
const (
	StateKeyRawFindings      = "raw_findings"
	StateKeyFilteredFindings = "filtered_findings"
	StateKeyHardExcluded     = "hard_excluded"
	StateKeyHardFilterStats  = "hard_filter_stats"
	StateKeyAnalysisSummary  = "analysis_summary"
	StateKeyValidationResult = "validation_result"
	StateKeyAutofixResult    = "autofix_result"
)

package findings

// Severity levels used in findings.
const (
	SeverityHigh   = "HIGH"
	SeverityMedium = "MEDIUM"
	SeverityLow    = "LOW"
)

// Finding represents a single security vulnerability found during analysis.
type Finding struct {
	File            string  `json:"file"`
	Line            int     `json:"line"`
	Severity        string  `json:"severity"`
	Category        string  `json:"category"`
	Description     string  `json:"description"`
	ExploitScenario string  `json:"exploit_scenario"`
	Recommendation  string  `json:"recommendation"`
	Confidence      float64 `json:"confidence"`
	Autofix         string  `json:"autofix,omitempty"`
}

// AnalysisSummary holds the scanner's self-reported summary.
type AnalysisSummary struct {
	FilesReviewed   int  `json:"files_reviewed"`
	HighSeverity    int  `json:"high_severity"`
	MediumSeverity  int  `json:"medium_severity"`
	LowSeverity     int  `json:"low_severity"`
	ReviewCompleted bool `json:"review_completed"`
}

// ScanResult is the structured output from the scanner agent.
type ScanResult struct {
	Findings        []Finding       `json:"findings"`
	AnalysisSummary AnalysisSummary `json:"analysis_summary"`
}

// ValidationResult is the structured output from the validator agent for a single finding.
type ValidationResult struct {
	KeepFinding     bool    `json:"keep_finding"`
	ConfidenceScore float64 `json:"confidence_score"`
	ExclusionReason string  `json:"exclusion_reason,omitempty"`
	Justification   string  `json:"justification"`
}

// AutofixResult is the structured output from the autofixer agent for a single finding.
type AutofixResult struct {
	Autofix string `json:"autofix"`
}

// FilterStats tracks how many findings were kept/excluded at each stage.
type FilterStats struct {
	TotalFindings int `json:"total_findings"`
	HardExcluded  int `json:"hard_excluded"`
	LLMExcluded   int `json:"llm_excluded"`
	KeptFindings  int `json:"kept_findings"`
}

// ExcludedFinding pairs a finding with its exclusion reason.
type ExcludedFinding struct {
	Finding Finding `json:"finding"`
	Reason  string  `json:"reason"`
}

// PipelineResult holds the complete output of the agent pipeline.
type PipelineResult struct {
	Findings ScanOutput `json:"findings"`
}

// ScanOutput is the final output written to disk and stdout.
type ScanOutput struct {
	Findings []Finding         `json:"findings"`
	Stats    FilterStats       `json:"stats"`
	Excluded []ExcludedFinding `json:"excluded,omitempty"`
}

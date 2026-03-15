package findings

import "google.golang.org/genai"

// ScanResultSchema returns the Gemini ResponseSchema that constrains the
// scanner agent to produce valid JSON matching the ScanResult type.
func ScanResultSchema() *genai.Schema {
	return &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"findings": {
				Type:  genai.TypeArray,
				Items: findingSchema(),
			},
			"analysis_summary": analysisSummarySchema(),
		},
		Required: []string{"findings", "analysis_summary"},
	}
}

// ValidationResultSchema returns the Gemini ResponseSchema that constrains the
// validator agent to produce valid JSON matching the ValidationResult type.
func ValidationResultSchema() *genai.Schema {
	return &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"keep_finding": {
				Type:        genai.TypeBoolean,
				Description: "Whether the finding should be kept (true) or excluded as false positive (false)",
			},
			"confidence_score": {
				Type:        genai.TypeNumber,
				Description: "Confidence score from 1-10 where 10 is highest confidence the finding is real",
			},
			"exclusion_reason": {
				Type:        genai.TypeString,
				Description: "Reason for excluding the finding, empty if kept",
			},
			"justification": {
				Type:        genai.TypeString,
				Description: "Brief explanation of the analysis decision",
			},
		},
		Required: []string{"keep_finding", "confidence_score", "justification"},
	}
}

// AutofixResultSchema returns the Gemini ResponseSchema that constrains the
// autofixer agent to produce valid JSON matching the AutofixResult type.
func AutofixResultSchema() *genai.Schema {
	return &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"autofix": {
				Type:        genai.TypeString,
				Description: "The fixed code snippet that resolves the vulnerability. Provide ONLY the replaced code content.",
			},
		},
		Required: []string{"autofix"},
	}
}

func findingSchema() *genai.Schema {
	return &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"file": {
				Type:        genai.TypeString,
				Description: "Path to the file containing the vulnerability",
			},
			"line": {
				Type:        genai.TypeInteger,
				Description: "Line number where the vulnerability is located",
			},
			"severity": {
				Type:        genai.TypeString,
				Enum:        []string{SeverityHigh, SeverityMedium, SeverityLow},
				Description: "Severity of the vulnerability",
			},
			"category": {
				Type:        genai.TypeString,
				Description: "Category such as sql_injection, xss, command_injection, etc.",
			},
			"description": {
				Type:        genai.TypeString,
				Description: "Description of the vulnerability",
			},
			"exploit_scenario": {
				Type:        genai.TypeString,
				Description: "Concrete exploit scenario demonstrating the attack path",
			},
			"recommendation": {
				Type:        genai.TypeString,
				Description: "Recommended fix for the vulnerability",
			},
			"confidence": {
				Type:        genai.TypeNumber,
				Description: "Confidence score from 0.0 to 1.0",
			},
			"autofix": {
				Type:        genai.TypeString,
				Description: "Optional autofix snippet generated for the finding",
			},
		},
		Required: []string{"file", "line", "severity", "category", "description", "exploit_scenario", "recommendation", "confidence"},
	}
}

func analysisSummarySchema() *genai.Schema {
	return &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"files_reviewed": {
				Type: genai.TypeInteger,
			},
			"high_severity": {
				Type: genai.TypeInteger,
			},
			"medium_severity": {
				Type: genai.TypeInteger,
			},
			"low_severity": {
				Type: genai.TypeInteger,
			},
			"review_completed": {
				Type: genai.TypeBoolean,
			},
		},
		Required: []string{"files_reviewed", "high_severity", "medium_severity", "low_severity", "review_completed"},
	}
}

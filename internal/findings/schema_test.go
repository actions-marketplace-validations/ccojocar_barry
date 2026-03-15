package findings

import (
	"testing"

	"google.golang.org/genai"
)

func TestScanResultSchema(t *testing.T) {
	s := ScanResultSchema()
	if s.Type != genai.TypeObject {
		t.Errorf("type = %v, want TypeObject", s.Type)
	}
	requiredFields := map[string]bool{"findings": false, "analysis_summary": false}
	for _, r := range s.Required {
		requiredFields[r] = true
	}
	for k, found := range requiredFields {
		if !found {
			t.Errorf("missing required field %q", k)
		}
	}
	findingsProp, ok := s.Properties["findings"]
	if !ok {
		t.Fatal("missing 'findings' property")
	}
	if findingsProp.Type != genai.TypeArray {
		t.Errorf("findings type = %v, want TypeArray", findingsProp.Type)
	}
	if findingsProp.Items == nil {
		t.Fatal("findings.Items is nil")
	}
	// Verify finding schema has all expected fields.
	findingFields := []string{"file", "line", "severity", "category", "description", "exploit_scenario", "recommendation", "confidence"}
	for _, f := range findingFields {
		if _, ok := findingsProp.Items.Properties[f]; !ok {
			t.Errorf("finding schema missing field %q", f)
		}
	}
	if len(findingsProp.Items.Required) != len(findingFields) {
		t.Errorf("finding required fields = %d, want %d", len(findingsProp.Items.Required), len(findingFields))
	}
	// Verify severity enum.
	sevProp := findingsProp.Items.Properties["severity"]
	if len(sevProp.Enum) != 3 {
		t.Errorf("severity enum count = %d, want 3", len(sevProp.Enum))
	}
	// Verify analysis_summary.
	summaryProp, ok := s.Properties["analysis_summary"]
	if !ok {
		t.Fatal("missing 'analysis_summary' property")
	}
	summaryFields := []string{"files_reviewed", "high_severity", "medium_severity", "low_severity", "review_completed"}
	for _, f := range summaryFields {
		if _, ok := summaryProp.Properties[f]; !ok {
			t.Errorf("analysis_summary missing field %q", f)
		}
	}
	if summaryProp.Properties["review_completed"].Type != genai.TypeBoolean {
		t.Error("review_completed should be TypeBoolean")
	}
}

func TestValidationResultSchema(t *testing.T) {
	s := ValidationResultSchema()
	if s.Type != genai.TypeObject {
		t.Errorf("type = %v, want TypeObject", s.Type)
	}
	// Check required fields.
	requiredSet := make(map[string]bool)
	for _, r := range s.Required {
		requiredSet[r] = true
	}
	for _, want := range []string{"keep_finding", "confidence_score", "justification"} {
		if !requiredSet[want] {
			t.Errorf("missing required field %q", want)
		}
	}
	if requiredSet["exclusion_reason"] {
		t.Error("exclusion_reason should NOT be required")
	}
	// Check types.
	if s.Properties["keep_finding"].Type != genai.TypeBoolean {
		t.Error("keep_finding should be TypeBoolean")
	}
	if s.Properties["confidence_score"].Type != genai.TypeNumber {
		t.Error("confidence_score should be TypeNumber")
	}
	if s.Properties["justification"].Type != genai.TypeString {
		t.Error("justification should be TypeString")
	}
}

func TestAutofixResultSchema(t *testing.T) {
	s := AutofixResultSchema()
	if s.Type != genai.TypeObject {
		t.Errorf("type = %v, want TypeObject", s.Type)
	}
	if len(s.Required) != 1 || s.Required[0] != "autofix" {
		t.Errorf("required fields = %v, want [autofix]", s.Required)
	}
	if s.Properties["autofix"].Type != genai.TypeString {
		t.Error("autofix should be TypeString")
	}
}

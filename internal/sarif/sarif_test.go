package sarif_test

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/cosmin/barry/internal/findings"
	"github.com/cosmin/barry/internal/sarif"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed testdata/sarif-schema-2.1.0.json
var sarifSchemaJSON []byte

var (
	compiledSchemaOnce sync.Once
	compiledSchema     *jsonschema.Schema
	compiledSchemaErr  error
)

func validateSchema(t *testing.T, report *sarif.Report) {
	t.Helper()

	compiledSchemaOnce.Do(func() {
		schema, err := jsonschema.UnmarshalJSON(bytes.NewReader(sarifSchemaJSON))
		if err != nil {
			compiledSchemaErr = fmt.Errorf("unmarshal sarif schema: %w", err)
			return
		}
		compiler := jsonschema.NewCompiler()
		if err := compiler.AddResource(sarif.Schema, schema); err != nil {
			compiledSchemaErr = fmt.Errorf("add schema resource: %w", err)
			return
		}
		compiledSchema, compiledSchemaErr = compiler.Compile(sarif.Schema)
	})

	if compiledSchemaErr != nil {
		t.Fatalf("schema compilation failed: %v", compiledSchemaErr)
	}

	raw, err := json.MarshalIndent(report, "", "\t")
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}

	data, err := jsonschema.UnmarshalJSON(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("unmarshal for validation: %v", err)
	}

	if err := compiledSchema.Validate(data); err != nil {
		t.Fatalf("SARIF schema validation failed:\n%v\n\nGenerated JSON:\n%s", err, raw)
	}
}

func TestEmptyReport(t *testing.T) {
	output := &findings.ScanOutput{
		Findings: nil,
		Stats:    findings.FilterStats{},
	}
	report := sarif.GenerateReport(output, "1.0.0")

	if report.Version != sarif.Version {
		t.Errorf("version = %q, want %q", report.Version, sarif.Version)
	}
	if report.Schema != sarif.Schema {
		t.Errorf("schema = %q, want %q", report.Schema, sarif.Schema)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(report.Runs))
	}
	if report.Runs[0].Tool.Driver.Name != "barry" {
		t.Errorf("driver name = %q, want %q", report.Runs[0].Tool.Driver.Name, "barry")
	}

	validateSchema(t, report)
}

func TestSingleFinding(t *testing.T) {
	output := &findings.ScanOutput{
		Findings: []findings.Finding{
			{
				File:            "src/main.go",
				Line:            42,
				Severity:        "HIGH",
				Category:        "SQL Injection",
				Description:     "User input passed directly to SQL query",
				ExploitScenario: "Attacker sends crafted input via HTTP param",
				Recommendation:  "Use parameterized queries",
				Confidence:      0.9,
			},
		},
		Stats: findings.FilterStats{TotalFindings: 1, KeptFindings: 1},
	}

	report := sarif.GenerateReport(output, "1.2.3")

	validateSchema(t, report)

	if len(report.Runs[0].Results) != 1 {
		t.Fatalf("results = %d, want 1", len(report.Runs[0].Results))
	}
	r := report.Runs[0].Results[0]
	if r.RuleID != "BARRY/sql-injection" {
		t.Errorf("ruleId = %q, want %q", r.RuleID, "BARRY/sql-injection")
	}
	if r.Level != "error" {
		t.Errorf("level = %q, want %q", r.Level, "error")
	}
	if len(r.Locations) != 1 {
		t.Fatalf("locations = %d, want 1", len(r.Locations))
	}
	loc := r.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "src/main.go" {
		t.Errorf("uri = %q, want %q", loc.ArtifactLocation.URI, "src/main.go")
	}
	if loc.Region.StartLine != 42 {
		t.Errorf("startLine = %d, want 42", loc.Region.StartLine)
	}

	rules := report.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].ID != "BARRY/sql-injection" {
		t.Errorf("rule id = %q, want %q", rules[0].ID, "BARRY/sql-injection")
	}
}

func TestMultipleFindingsSameCategory(t *testing.T) {
	output := &findings.ScanOutput{
		Findings: []findings.Finding{
			{File: "a.go", Line: 10, Severity: "HIGH", Category: "XSS", Description: "First XSS finding", Confidence: 0.8},
			{File: "b.go", Line: 20, Severity: "HIGH", Category: "XSS", Description: "Second XSS finding", Confidence: 0.7},
		},
	}

	report := sarif.GenerateReport(output, "1.0.0")
	validateSchema(t, report)

	rules := report.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}

	for i, r := range report.Runs[0].Results {
		if r.RuleIndex != 0 {
			t.Errorf("result[%d].ruleIndex = %d, want 0", i, r.RuleIndex)
		}
	}
}

func TestMultipleCategories(t *testing.T) {
	output := &findings.ScanOutput{
		Findings: []findings.Finding{
			{File: "a.go", Line: 1, Severity: "HIGH", Category: "SQL Injection", Description: "desc1", Confidence: 0.9},
			{File: "b.go", Line: 2, Severity: "MEDIUM", Category: "XSS", Description: "desc2", Confidence: 0.6},
			{File: "c.go", Line: 3, Severity: "LOW", Category: "Info Leak", Description: "desc3", Confidence: 0.3},
		},
	}

	report := sarif.GenerateReport(output, "0.1.0")
	validateSchema(t, report)

	if len(report.Runs[0].Tool.Driver.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(report.Runs[0].Tool.Driver.Rules))
	}
	if len(report.Runs[0].Results) != 3 {
		t.Fatalf("results = %d, want 3", len(report.Runs[0].Results))
	}
}

func TestSeverityMapping(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"HIGH", "error"},
		{"MEDIUM", "warning"},
		{"LOW", "note"},
		{"UNKNOWN", "warning"},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			output := &findings.ScanOutput{
				Findings: []findings.Finding{
					{File: "f.go", Line: 1, Severity: tt.severity, Category: "test", Description: "d", Confidence: 0.5},
				},
			}
			report := sarif.GenerateReport(output, "1.0.0")
			validateSchema(t, report)
			if report.Runs[0].Results[0].Level != tt.want {
				t.Errorf("severity %q -> level %q, want %q", tt.severity, report.Runs[0].Results[0].Level, tt.want)
			}
		})
	}
}

func TestWriteReport(t *testing.T) {
	output := &findings.ScanOutput{
		Findings: []findings.Finding{
			{File: "test.go", Line: 5, Severity: "MEDIUM", Category: "Hardcoded Secret", Description: "API key in source", Confidence: 0.85},
		},
	}

	var buf bytes.Buffer
	if err := sarif.WriteReport(&buf, output, "2.0.0"); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}

	var report sarif.Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal written report: %v", err)
	}
	validateSchema(t, &report)
}

func TestWriteReportEmpty(t *testing.T) {
	output := &findings.ScanOutput{}

	var buf bytes.Buffer
	if err := sarif.WriteReport(&buf, output, "1.0.0"); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}

	var report sarif.Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	validateSchema(t, &report)
}

func TestFindingWithAutofix(t *testing.T) {
	output := &findings.ScanOutput{
		Findings: []findings.Finding{
			{
				File:        "handler.go",
				Line:        10,
				Severity:    "HIGH",
				Category:    "sqli",
				Description: "SQL injection",
				Confidence:  0.9,
				Autofix:     "db.Query(ctx, stmt, params...)",
			},
		},
	}
	report := sarif.GenerateReport(output, "1.0.0")
	validateSchema(t, report)

	r := report.Runs[0].Results[0]
	if len(r.Fixes) != 1 {
		t.Fatalf("fixes = %d, want 1", len(r.Fixes))
	}
	if r.Fixes[0].ArtifactChanges[0].Replacements[0].InsertedContent.Text != "db.Query(ctx, stmt, params...)" {
		t.Error("autofix content mismatch")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("write failed") }

func TestWriteReport_WriteError(t *testing.T) {
	output := &findings.ScanOutput{}
	err := sarif.WriteReport(errWriter{}, output, "1.0.0")
	if err == nil {
		t.Fatal("expected error from failing writer")
	}
}

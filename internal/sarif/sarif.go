// Package sarif provides SARIF 2.1.0 output generation for Barry findings.
// The types defined here cover only the subset of the SARIF specification
// required to produce valid reports for GitHub Code Scanning / Security Center.
package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/cosmin/barry/internal/findings"
)

// SARIF 2.1.0 constants.
const (
	Version = "2.1.0"
	Schema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

	toolName    = "barry"
	toolInfoURI = "https://github.com/cosmin/barry"
	levelError  = "error"
	levelWarn   = "warning"
	levelNote   = "note"
)

// --- SARIF 2.1.0 types (minimal subset) ---

// Report is the top-level SARIF log object.
type Report struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []*Run `json:"runs"`
}

// Run describes a single run of an analysis tool.
type Run struct {
	Tool    *Tool     `json:"tool"`
	Results []*Result `json:"results"`
}

// Tool describes the analysis tool.
type Tool struct {
	Driver *ToolComponent `json:"driver"`
}

// ToolComponent describes the tool driver (name, version, rules).
type ToolComponent struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version,omitempty"`
	SemanticVersion string                 `json:"semanticVersion,omitempty"`
	InformationURI  string                 `json:"informationUri,omitempty"`
	Rules           []*ReportingDescriptor `json:"rules,omitempty"`
}

// ReportingDescriptor describes a rule (finding category).
type ReportingDescriptor struct {
	ID                   string                    `json:"id"`
	Name                 string                    `json:"name,omitempty"`
	ShortDescription     *MultiformatMessageString `json:"shortDescription,omitempty"`
	FullDescription      *MultiformatMessageString `json:"fullDescription,omitempty"`
	HelpURI              string                    `json:"helpUri,omitempty"`
	Help                 *MultiformatMessageString `json:"help,omitempty"`
	DefaultConfiguration *ReportingConfiguration   `json:"defaultConfiguration,omitempty"`
	Properties           map[string]interface{}    `json:"properties,omitempty"`
}

// ReportingConfiguration holds the default level for a rule.
type ReportingConfiguration struct {
	Level string `json:"level,omitempty"`
}

// MultiformatMessageString holds a message in plain text (and optionally Markdown).
type MultiformatMessageString struct {
	Text string `json:"text"`
}

// Result is a single finding.
type Result struct {
	RuleID    string      `json:"ruleId,omitempty"`
	RuleIndex int         `json:"ruleIndex,omitempty"`
	Level     string      `json:"level,omitempty"`
	Message   *Message    `json:"message"`
	Locations []*Location `json:"locations,omitempty"`
	Fixes     []*Fix      `json:"fixes,omitempty"`
}

// Fix describes a proposed fix for the problem.
type Fix struct {
	Description     *Message          `json:"description,omitempty"`
	ArtifactChanges []*ArtifactChange `json:"artifactChanges"`
}

// ArtifactChange describes a change to a single file.
type ArtifactChange struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation"`
	Replacements     []*Replacement    `json:"replacements"`
}

// Replacement describes a single text replacement.
type Replacement struct {
	DeletedRegion   *Region          `json:"deletedRegion"`
	InsertedContent *ArtifactContent `json:"insertedContent,omitempty"`
}

// Message holds a text message.
type Message struct {
	Text string `json:"text"`
}

// Location points to a physical location in a source file.
type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
}

// PhysicalLocation pairs an artifact location with a region.
type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *Region           `json:"region,omitempty"`
}

// ArtifactLocation identifies a file.
type ArtifactLocation struct {
	URI       string `json:"uri,omitempty"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// Region identifies a span within a file.
type Region struct {
	StartLine   int              `json:"startLine,omitempty"`
	StartColumn int              `json:"startColumn,omitempty"`
	Snippet     *ArtifactContent `json:"snippet,omitempty"`
}

// ArtifactContent holds the text of a code snippet.
type ArtifactContent struct {
	Text string `json:"text,omitempty"`
}

// --- Builder / converter ---

// GenerateReport converts Barry scan output into a SARIF Report.
func GenerateReport(output *findings.ScanOutput, barryVersion string) *Report {
	rules := map[string]int{}
	ruleList := []*ReportingDescriptor{}
	results := []*Result{}

	for _, f := range output.Findings {
		ruleIdx, ok := rules[f.Category]
		if !ok {
			ruleIdx = len(ruleList)
			rules[f.Category] = ruleIdx
			ruleList = append(ruleList, buildRule(f))
		}

		results = append(results, &Result{
			RuleID:    ruleID(f.Category),
			RuleIndex: ruleIdx,
			Level:     severityToLevel(f.Severity),
			Message:   &Message{Text: buildMessage(f)},
			Locations: []*Location{buildLocation(f)},
			Fixes:     buildFix(f),
		})
	}

	driver := &ToolComponent{
		Name:            toolName,
		Version:         barryVersion,
		SemanticVersion: barryVersion,
		InformationURI:  toolInfoURI,
		Rules:           ruleList,
	}

	return &Report{
		Schema:  Schema,
		Version: Version,
		Runs: []*Run{{
			Tool:    &Tool{Driver: driver},
			Results: results,
		}},
	}
}

// WriteReport serialises a SARIF report as indented JSON to w.
func WriteReport(w io.Writer, output *findings.ScanOutput, barryVersion string) error {
	report := GenerateReport(output, barryVersion)
	raw, err := json.MarshalIndent(report, "", "\t")
	if err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

// --- helpers ---

func ruleID(category string) string {
	id := strings.ToLower(category)
	id = strings.ReplaceAll(id, " ", "-")
	return "BARRY/" + id
}

func buildRule(f findings.Finding) *ReportingDescriptor {
	level := severityToLevel(f.Severity)
	return &ReportingDescriptor{
		ID:               ruleID(f.Category),
		Name:             f.Category,
		ShortDescription: &MultiformatMessageString{Text: f.Category},
		FullDescription:  &MultiformatMessageString{Text: f.Description},
		Help: &MultiformatMessageString{
			Text: fmt.Sprintf("%s\nSeverity: %s\nRecommendation: %s", f.Description, f.Severity, f.Recommendation),
		},
		DefaultConfiguration: &ReportingConfiguration{Level: level},
		Properties: map[string]interface{}{
			"tags":      []string{"security", strings.ToLower(f.Severity)},
			"precision": confidenceToTag(f.Confidence),
		},
	}
}

func buildLocation(f findings.Finding) *Location {
	return &Location{
		PhysicalLocation: &PhysicalLocation{
			ArtifactLocation: &ArtifactLocation{
				URI:       f.File,
				URIBaseID: "%SRCROOT%",
			},
			Region: &Region{
				StartLine:   f.Line,
				StartColumn: 1,
			},
		},
	}
}

func buildFix(f findings.Finding) []*Fix {
	if f.Autofix == "" {
		return nil
	}

	return []*Fix{
		{
			Description: &Message{Text: "Apply AI-generated fix"},
			ArtifactChanges: []*ArtifactChange{
				{
					ArtifactLocation: &ArtifactLocation{
						URI:       f.File,
						URIBaseID: "%SRCROOT%",
					},
					Replacements: []*Replacement{
						{
							DeletedRegion: &Region{
								StartLine:   f.Line,
								StartColumn: 1,
							},
							InsertedContent: &ArtifactContent{
								Text: f.Autofix,
							},
						},
					},
				},
			},
		},
	}
}

func buildMessage(f findings.Finding) string {
	msg := f.Description
	if f.ExploitScenario != "" {
		msg += "\n\nExploit scenario: " + f.ExploitScenario
	}
	if f.Recommendation != "" {
		msg += "\n\nRecommendation: " + f.Recommendation
	}
	return msg
}

func severityToLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case findings.SeverityHigh:
		return levelError
	case findings.SeverityMedium:
		return levelWarn
	case findings.SeverityLow:
		return levelNote
	default:
		return levelWarn
	}
}

func confidenceToTag(confidence float64) string {
	switch {
	case confidence >= 0.8:
		return "high"
	case confidence >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

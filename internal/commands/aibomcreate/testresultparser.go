package aibomcreate

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/samber/lo"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
)

// PolicyTestIssue represents a single CLI policy test issue for display.
type PolicyTestIssue struct {
	ID                string `json:"id"`
	Description       string `json:"description"`
	Severity          string `json:"severity"`
	PolicyID          string `json:"policy_id"`
	State             string `json:"state"`
	Source            string `json:"source"`
	RemediationAdvice string `json:"remediation_advice"`
}

// TestResult is the parsed test result used for pretty and JSON output.
type TestResult struct {
	Issues  []PolicyTestIssue `json:"issues"`
	Summary []byte            `json:"summary"`
}

// severityLevel returns the index in DEFAULT_SEVERITIES for ordering (higher = more severe).
// Unknown severities return -1 so they sort last.
func severityLevel(s string) int {
	idx := slices.IndexFunc(json_schemas.DEFAULT_SEVERITIES, func(sev string) bool {
		return strings.EqualFold(sev, s)
	})
	return idx
}

func buildTestSummary(issues []PolicyTestIssue) ([]byte, error) {
	bySeverity := lo.GroupBy(issues, func(issue PolicyTestIssue) string {
		return issue.Severity
	})

	summary := json_schemas.TestSummary{}
	for severity, issues := range bySeverity {
		openCount := lo.CountBy(issues, func(issue PolicyTestIssue) bool {
			return issue.State == "open"
		})
		summary.Results = append(summary.Results, json_schemas.TestSummaryResult{
			Severity: severity,
			Total:    len(issues),
			Open:     openCount,
			Ignored:  len(issues) - openCount,
		})
	}
	data, err := json.Marshal(summary)
	if err != nil {
		return nil, fmt.Errorf("marshal test summary: %w", err)
	}
	return data, nil
}

// ParseTestResult unmarshals the API JSON string into TestResult.
func ParseTestResult(jsonStr string) (*TestResult, error) {
	var raw rawTestResponse
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("parse test result: %w", err)
	}
	issues := raw.Data.Attributes.Issues
	slices.SortFunc(issues, func(a, b PolicyTestIssue) int {
		sa, sb := severityLevel(a.Severity), severityLevel(b.Severity)
		if sa != sb {
			return sb - sa // higher severity first
		}
		if a.ID != b.ID {
			return strings.Compare(a.ID, b.ID)
		}
		return strings.Compare(a.Description, b.Description)
	})
	// filter out closed issues
	issues = lo.Filter(issues, func(issue PolicyTestIssue, _ int) bool {
		return issue.State == "open" || issue.State == "ignored"
	})
	summaryPayload, err := buildTestSummary(issues)
	if err != nil {
		return nil, fmt.Errorf("failed to build test summary: %w", err)
	}

	return &TestResult{
		Issues:  issues,
		Summary: summaryPayload,
	}, nil
}

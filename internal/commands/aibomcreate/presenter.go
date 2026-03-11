package aibomcreate

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"golang.org/x/exp/slices"
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

// TestResultPresentation is the parsed test result used for pretty and JSON output.
type TestResultPresentation struct {
	OK      bool              `json:"ok"`
	Issues  []PolicyTestIssue `json:"issues"`
	Summary string            `json:"summary"`
}

// rawTestResponse mirrors the API response for parsing (snake_case).
type rawTestResponse struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Issues []PolicyTestIssue `json:"issues"`
		} `json:"attributes"`
	} `json:"data"`
}

// severityLevel for ordering (higher = more severe).
func severityLevel(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

var (
	lowStyle      = lipgloss.NewStyle().Foreground(lipgloss.NoColor{})
	mediumStyle   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "11", Dark: "3"})
	highStyle     = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "9", Dark: "1"})
	criticalStyle = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "13", Dark: "5"})
	sectionStyle  = lipgloss.NewStyle().Bold(true)
	boxStyle      = lipgloss.NewStyle().
			PaddingLeft(2).
			PaddingRight(4).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.NoColor{})
)

func styleForSeverity(severity string) lipgloss.Style {
	switch strings.ToLower(severity) {
	case "critical":
		return criticalStyle
	case "high":
		return highStyle
	case "medium":
		return mediumStyle
	default:
		return lowStyle
	}
}

// ParseTestResult unmarshals the API JSON string into TestResultPresentation.
func ParseTestResult(jsonStr string) (*TestResultPresentation, error) {
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
	total := len(issues)
	summary := fmt.Sprintf("Found %d issue(s)", total)
	if total == 0 {
		summary = "No issues found"
	}
	return &TestResultPresentation{
		OK:      total == 0,
		Issues:  issues,
		Summary: summary,
	}, nil
}

// RenderPrettyResult writes a human-readable test result to w.
func RenderPrettyResult(invocationCtx workflow.InvocationContext, w io.Writer, res *TestResultPresentation) error {
	config := invocationCtx.GetConfiguration()
	title := sectionStyle.Render("AI BOM policy test")
	_, _ = fmt.Fprintf(w, "\n%s\n\n", title)

	issuesBlock := renderIssues(config.GetString(configuration.API_URL), res.Issues)
	_, _ = fmt.Fprintln(w, issuesBlock)

	summaryBlock := renderSummary(res)
	_, _ = fmt.Fprintln(w, boxStyle.Render(summaryBlock))
	return nil
}

func makePolicyURL(baseURL, policyID string) string {
	if !strings.Contains(baseURL, "api.") {
		return policyID
	}
	baseURL = strings.Replace(baseURL, "api.", "evo.", 1)
	return fmt.Sprintf("%s/policies/%s", baseURL, policyID)
}

func renderIssues(baseURL string, issues []PolicyTestIssue) string {
	if len(issues) == 0 {
		return sectionStyle.Render("Open issues:") + "\n  No issues found."
	}
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Open issues:"))
	b.WriteString("\n")
	for _, iss := range issues {
		style := styleForSeverity(iss.Severity)
		sevStr := style.Render(fmt.Sprintf("× [%s]", strings.ToUpper(iss.Severity)))
		descStr := sectionStyle.Render(iss.Description)
		b.WriteString(fmt.Sprintf("\n%s %s\n", sevStr, descStr))
		if iss.PolicyID != "" {
			b.WriteString(fmt.Sprintf("  Policy: %s\n", makePolicyURL(baseURL, iss.PolicyID)))
		}
		if iss.RemediationAdvice != "" {
			b.WriteString(fmt.Sprintf("  Remediation: %s\n", iss.RemediationAdvice))
		}
	}
	return b.String()
}

func renderSummary(res *TestResultPresentation) string {
	total := len(res.Issues)
	bySev := make(map[string]int)
	for _, iss := range res.Issues {
		bySev[strings.ToLower(iss.Severity)]++
	}
	parts := []string{fmt.Sprintf("  Test summary\n  Open issues: %d", total)}
	order := []string{"critical", "high", "medium", "low"}
	for _, sev := range order {
		if n := bySev[sev]; n > 0 {
			style := styleForSeverity(sev)
			parts = append(parts, style.Render(fmt.Sprintf("%d %s", n, strings.ToUpper(sev))))
		}
	}
	// single line like "Open issues: 2 [2 HIGH]"
	if total > 0 {
		var counts []string
		for _, sev := range order {
			if n := bySev[sev]; n > 0 {
				style := styleForSeverity(sev)
				counts = append(counts, style.Render(fmt.Sprintf("%d %s", n, strings.ToUpper(sev))))
			}
		}
		return fmt.Sprintf("  Test summary\n  Open issues: %d [%s]", total, strings.Join(counts, " "))
	}
	return fmt.Sprintf("  Test summary\n  Open issues: %d", total)
}

// RenderJSONResult writes the test result as JSON to w (for machine-readable output).
func RenderJSONResult(w io.Writer, res *TestResultPresentation) error {
	if err := json.NewEncoder(w).Encode(res); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

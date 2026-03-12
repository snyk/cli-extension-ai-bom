package aibomcreate

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

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

// RenderPrettyResult writes a human-readable test result to w.
func RenderPrettyResult(invocationCtx workflow.InvocationContext, w io.Writer, res *TestResult) error {
	config := invocationCtx.GetConfiguration()
	title := sectionStyle.Render("AI BOM policy test")
	_, _ = fmt.Fprintf(w, "\n%s\n\n", title)

	openIssues := filterIssuesByState(res.Issues, "open")
	ignoredIssues := filterIssuesByState(res.Issues, "ignored")

	issuesBlock := renderIssues(config.GetString(configuration.API_URL), openIssues, ignoredIssues)
	_, _ = fmt.Fprintln(w, issuesBlock)

	summaryBlock := renderSummary(openIssues, ignoredIssues)
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

func renderIssues(baseURL string, openIssues, ignoredIssues []PolicyTestIssue) string {
	return renderIssuesForState(baseURL, "Open", openIssues) + "\n" + renderIssuesForState(baseURL, "Ignored", ignoredIssues)
}

func renderIssuesForState(baseURL, label string, issues []PolicyTestIssue) string {
	if len(issues) == 0 {
		return sectionStyle.Render(label+" issues:") + "\n  No issues found."
	}
	var b strings.Builder
	b.WriteString(sectionStyle.Render(label + " issues:"))
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

func renderSummary(openIssues, ignoredIssues []PolicyTestIssue) string {
	lines := append([]string{},
		"  Test summary",
		renderSummaryForState("Open", openIssues),
		renderSummaryForState("Ignored", ignoredIssues),
	)
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

func filterIssuesByState(issues []PolicyTestIssue, state string) []PolicyTestIssue {
	var out []PolicyTestIssue
	for _, iss := range issues {
		if strings.EqualFold(iss.State, state) {
			out = append(out, iss)
		}
	}
	return out
}

func renderSummaryForState(label string, issues []PolicyTestIssue) string {
	total := len(issues)
	bySev := make(map[string]int)
	for _, iss := range issues {
		bySev[strings.ToLower(iss.Severity)]++
	}
	order := json_schemas.DEFAULT_SEVERITIES
	if total > 0 {
		var counts []string
		for _, sev := range order {
			if n := bySev[sev]; n > 0 {
				style := styleForSeverity(sev)
				counts = append(counts, style.Render(fmt.Sprintf("%d %s", n, strings.ToUpper(sev))))
			}
		}
		return fmt.Sprintf("  %s issues: %d [%s]", label, total, strings.Join(counts, " "))
	}
	return fmt.Sprintf("  %s issues: %d", label, total)
}

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
)

func (m *Model) View() string {
	if m.Width == 0 {
		return "Loading..."
	}

	var s strings.Builder

	// 1. Always Render Welcome Header (Title + Dog)
	s.WriteString(renderWelcomeHeader())
	s.WriteString("\n\n")

	// 2. Render History or Scan Context
	if m.Step >= StepScanning {
		s.WriteString(renderScanContext(m))
	} else {
		s.WriteString(renderHistory(m))
	}

	// 3. Render Current Active Step
	s.WriteString(renderCurrentStep(m))

	return docStyle.Render(s.String())
}

func renderWelcomeHeader() string {
	return fmt.Sprintf("%s\n\n%s",
		lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			Height(3).
			Render("Snyk AI Red Teaming"),
		getDogArt(),
	)
}

func renderHistory(m *Model) string {
	var s strings.Builder

	// Define styles for completed questions
	qStyle := lipgloss.NewStyle().Foreground(special).Bold(true)
	aStyle := lipgloss.NewStyle().Foreground(subtle).PaddingLeft(2)

	// Helper to append a Q&A pair
	addQA := func(question, answer string) {
		s.WriteString(qStyle.Render(question))
		s.WriteString("\n")
		s.WriteString(aStyle.Render(answer))
		s.WriteString("\n\n")
	}

	// We check if we have passed the step to render its result
	if m.Step > StepTargetName {
		addQA("What is the name of your target?", m.Config.Target.Name)
	}
	if m.Step > StepTargetType {
		addQA("Target Type", m.Config.Target.Type)
	}
	if m.Step > StepTargetURL {
		addQA("What is the URL of the target?", m.Config.Target.Settings.URL)
	}
	if m.Step > StepTargetPurpose {
		addQA("What is the purpose/context of this target?", m.Config.Target.Context.Purpose)
	}
	if m.Step > StepResponseSelector {
		addQA("Where is the response located in the JSON?", m.Config.Target.Settings.ResponseSelector)
	}
	if m.Step > StepRequestBody {
		addQA("What is the request body template?", m.Config.Target.Settings.RequestBodyTemplate)
	}

	return s.String()
}

func renderScanContext(m *Model) string {
	var s strings.Builder
	aStyle := lipgloss.NewStyle().Foreground(subtle).PaddingLeft(2)

	// Target
	s.WriteString(lipgloss.NewStyle().Bold(true).Render("Target:"))
	s.WriteString("\n")
	s.WriteString(aStyle.Render(m.Config.Target.Name))
	s.WriteString("\n\n")

	// URL
	s.WriteString(lipgloss.NewStyle().Bold(true).Render("URL:"))
	s.WriteString("\n")
	s.WriteString(aStyle.Render(m.Config.Target.Settings.URL))
	s.WriteString("\n\n")

	// Headers
	if len(m.Config.Target.Settings.Headers) > 0 {
		s.WriteString(lipgloss.NewStyle().Bold(true).Render("Headers:"))
		s.WriteString("\n")
		for _, h := range m.Config.Target.Settings.Headers {
			s.WriteString(aStyle.Render(fmt.Sprintf("%s: ******", h.Name)))
			s.WriteString("\n")
		}
		s.WriteString("\n")
	}

	// Purpose (Context)
	if m.Config.Target.Context.Purpose != "" {
		s.WriteString(lipgloss.NewStyle().Bold(true).Render("Purpose:"))
		s.WriteString("\n")
		s.WriteString(aStyle.Render(m.Config.Target.Context.Purpose))
		s.WriteString("\n\n")
	}

	// Response Selector
	if m.Config.Target.Settings.ResponseSelector != "" {
		s.WriteString(lipgloss.NewStyle().Bold(true).Render("Response Selector:"))
		s.WriteString("\n")
		s.WriteString(aStyle.Render(m.Config.Target.Settings.ResponseSelector))
		s.WriteString("\n\n")
	}

	// Request Body Template
	if m.Config.Target.Settings.RequestBodyTemplate != "" {
		s.WriteString(lipgloss.NewStyle().Bold(true).Render("Request Body Template:"))
		s.WriteString("\n")
		s.WriteString(aStyle.Render(m.Config.Target.Settings.RequestBodyTemplate))
		s.WriteString("\n\n")
	}

	return s.String()
}

func renderConfigSummary(m *Model) string {
	var s strings.Builder
	aStyle := lipgloss.NewStyle().Foreground(subtle).PaddingLeft(2)

	// Manually format the config summary using the same style as history, but all at once
	s.WriteString(lipgloss.NewStyle().Bold(true).Render("Target Name:"))
	s.WriteString("\n")
	s.WriteString(aStyle.Render(m.Config.Target.Name))
	s.WriteString("\n\n")

	s.WriteString(lipgloss.NewStyle().Bold(true).Render("Target Type:"))
	s.WriteString("\n")
	s.WriteString(aStyle.Render(m.Config.Target.Type))
	s.WriteString("\n\n")

	s.WriteString(lipgloss.NewStyle().Bold(true).Render("Target URL:"))
	s.WriteString("\n")
	s.WriteString(aStyle.Render(m.Config.Target.Settings.URL))
	s.WriteString("\n\n")

	s.WriteString(lipgloss.NewStyle().Bold(true).Render("Target Purpose:"))
	s.WriteString("\n")
	s.WriteString(aStyle.Render(m.Config.Target.Context.Purpose))
	s.WriteString("\n\n")

	s.WriteString(lipgloss.NewStyle().Bold(true).Render("Response Selector:"))
	s.WriteString("\n")
	s.WriteString(aStyle.Render(m.Config.Target.Settings.ResponseSelector))
	s.WriteString("\n\n")

	s.WriteString(lipgloss.NewStyle().Bold(true).Render("Request Body Template:"))
	s.WriteString("\n")
	s.WriteString(aStyle.Render(m.Config.Target.Settings.RequestBodyTemplate))
	s.WriteString("\n")

	return s.String()
}

func renderCurrentStep(m *Model) string {
	switch m.Step {
	case StepWelcome:
		return lipgloss.NewStyle().Foreground(subtle).Render("Press Enter to get started")
	case StepAuthCheck:
		return fmt.Sprintf("%s\n\n%s\n\n%s",
			"We couldn't find a valid Organization ID.",
			stepStyle.Render("Press [Enter] to authenticate via web browser."),
			lipgloss.NewStyle().Foreground(subtle).Render("Press q to quit"),
		)
	case StepResults:
		return renderResults(m)
	case StepFindingDetails:
		return renderFindingDetails(m)
	case StepScanning:
		return renderScanning(m)
	case StepError:
		return fmt.Sprintf(
			"%s\n\n%s\n\n%s",
			errorStyle.Render(fmt.Sprintf("Error: %v", m.Err)),
			stepStyle.Render("Press 'e' or [Enter] to edit configuration and retry."),
			lipgloss.NewStyle().Foreground(subtle).Render("Press q to quit"),
		)
	case StepConfigConfirmation:
		return fmt.Sprintf(
			"%s\n\n%s\n\n%s",
			renderConfigSummary(m),
			stepStyle.Render("Configuration loaded from file. Is this correct? (y/n/e)"),
			lipgloss.NewStyle().Foreground(subtle).Render("Press q to quit"),
		)
	default:
		return renderFormStep(m)
	}
}

func renderScanning(m *Model) string {
	statusText := "Initializing scan..."
	// Only show running stats if we have a total greater than 0
	isRunning := m.ScanStatus == redteamclient.AIScanStatusStarted || m.ScanStatus == redteamclient.AIScanStatusSubmitted
	if isRunning && m.ScanTotal > 0 {
		statusText = fmt.Sprintf("Running scans (%d/%d completed)...", m.ScanDone, m.ScanTotal)
	} else if m.ScanStatus != "" && !isRunning && m.ScanStatus != redteamclient.AIScanStatusQueued {
		// Fallback for other states like failed/canceled
		statusText = fmt.Sprintf("Scan status: %s", m.ScanStatus)
	}

	return fmt.Sprintf(
		"%s %s\n\n%s\n\n%s\n",
		m.Spinner.View(),
		lipgloss.NewStyle().Bold(true).Render(statusText),
		m.Progress.View(),
		lipgloss.NewStyle().Foreground(subtle).Render("Press q to cancel"),
	)
}

func renderFormStep(m *Model) string {
	// Form Steps
	var content string
	var question string

	switch m.Step {
	case StepTargetName:
		question = "What is the name of your target?"
		content = m.Inputs[0].View()
	case StepTargetType:
		// The list model handles its own title and rendering
		return m.List.View()
	case StepTargetURL:
		question = "What is the URL of the target?"
		content = m.Inputs[1].View()
	case StepTargetPurpose:
		question = "What is the purpose/context of this target?"
		content = m.Inputs[2].View()
	case StepResponseSelector:
		question = "Where is the response located in the JSON? (e.g. 'response' or 'choices.0.message.content')"
		content = m.Inputs[3].View()
	case StepRequestBody:
		question = "What is the request body template? (Use {{prompt}} as placeholder)"
		content = m.Inputs[4].View()
	default:
		return ""
	}

	if m.Err != nil {
		content += "\n\n" + errorStyle.Render(fmt.Sprintf("Error: %v", m.Err))
	}

	if question != "" {
		return fmt.Sprintf(
			"%s\n\n%s\n\n%s",
			stepStyle.Render(question),
			content,
			lipgloss.NewStyle().Foreground(subtle).Render("Press Enter to continue, Esc to quit"),
		)
	}

	return ""
}

func renderResults(m *Model) string {
	var s strings.Builder

	s.WriteString(lipgloss.NewStyle().Bold(true).Render("Scan Results (Select a finding to view details):"))
	s.WriteString("\n\n")
	s.WriteString(m.ResultsTable.View())
	s.WriteString("\n\n")
	s.WriteString(lipgloss.NewStyle().Foreground(subtle).Render("Press q to exit, Enter to view details"))

	return s.String()
}

func renderFindingDetails(m *Model) string {
	var s strings.Builder

	s.WriteString(lipgloss.NewStyle().Bold(true).Render("Finding Details:"))
	s.WriteString("\n\n")
	s.WriteString(m.DetailViewport.View())
	s.WriteString("\n\n")
	s.WriteString(lipgloss.NewStyle().Foreground(subtle).Render("Press Esc/q to return to results"))

	return s.String()
}

func getDogArt() string {
	dog := `
      ,    /_
     /|   | |
   _/_\___/_|_
  /           \
 |  O       O  |
 |      ^      |
  \    ___    /
   \_______/
     | | |
    _| | |_
`
	return lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Render(dog)
}

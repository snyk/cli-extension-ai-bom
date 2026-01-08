package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
)

func formatFindingDetails(v *redteamclient.AIVulnerability) string {
	var s strings.Builder

	// Styles
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("240"))
	valStyle := lipgloss.NewStyle().PaddingLeft(2)

	// Header
	s.WriteString(titleStyle.Render(fmt.Sprintf("[%s] %s", v.Severity, v.Definition.Name)))
	s.WriteString("\n\n")

	// Description
	if v.Definition.Description != "" {
		s.WriteString(headerStyle.Render("Description:"))
		s.WriteString("\n")
		s.WriteString(valStyle.Render(v.Definition.Description))
		s.WriteString("\n\n")
	}

	// Evidence
	s.WriteString(headerStyle.Render("Evidence:"))
	s.WriteString("\n")
	s.WriteString(valStyle.Render(v.Evidence.Content.Reason))
	s.WriteString("\n\n")

	// Turns
	if len(v.Turns) > 0 {
		s.WriteString(headerStyle.Render("Conversation:"))
		s.WriteString("\n")
		for i, turn := range v.Turns {
			s.WriteString(fmt.Sprintf("Turn %d:\n", i+1))
			if turn.Request != nil {
				s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Render("User: "))
				s.WriteString(*turn.Request)
				s.WriteString("\n")
			}
			if turn.Response != nil {
				s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Render("AI:   "))
				s.WriteString(*turn.Response)
				s.WriteString("\n")
			}
			s.WriteString("\n")
		}
	}

	return s.String()
}

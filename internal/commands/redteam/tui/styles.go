package tui

import "github.com/charmbracelet/lipgloss"

var (
	subtle  = lipgloss.AdaptiveColor{Light: "#D9DCCF", Dark: "#999999"}
	special = lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}

	stepStyle = lipgloss.NewStyle().
			Foreground(special).
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("205")).
			Bold(true)

	docStyle = lipgloss.NewStyle().Margin(1, 2)
)

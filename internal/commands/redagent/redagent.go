package redagent

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func initialTextInputModel() *textInputModel {
	ti := textinput.New()
	ti.Placeholder = "Pikachu"
	ti.Focus()
	ti.CharLimit = 156
	ti.Width = 20

	return &textInputModel{
		textInput: ti,
		err:       nil,
	}
}

type (
	errMsg error
)

type textInputModel struct {
	textInput textinput.Model
	err       error
}

func (m *textInputModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m *textInputModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter, tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		default:
		}

	// We handle errors just like any other message
	case errMsg:
		m.err = msg
		return m, nil
	}

	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

func (m *textInputModel) View() string {
	inputStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1).
		Width(m.textInput.Width + 2)

	borderedInput := inputStyle.Render(m.textInput.View())

	return fmt.Sprintf(
		"What's your favorite Pokémon?\n\n%s\n\n%s",
		borderedInput,
		"(esc to quit)",
	) + "\n"
}

var WorkflowID = workflow.NewWorkflowIdentifier("redagent")

func RegisterWorkflows(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-ai-bom-redteam-agentic", pflag.ExitOnError)

	configuration := workflow.ConfigurationOptionsFromFlagset(flagset)

	if _, err := e.Register(WorkflowID, configuration, agenticWorkflow); err != nil {
		return fmt.Errorf("error while registering red agent workflow: %w", err)
	}
	return nil
}

func agenticWorkflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	logger := invocationCtx.GetEnhancedLogger()
	p := tea.NewProgram(initialTextInputModel())
	if _, err := p.Run(); err != nil {
		logger.Err(err).Msg("Error running TUI")
		return nil, fmt.Errorf("error running TUI: %w", err)
	}
	return nil, nil
}

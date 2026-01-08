package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/charmbracelet/bubbles/progress"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/snyk/go-application-framework/pkg/workflow"

	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
)

func Run(
	ctx context.Context,
	redTeamClient redteamclient.RedTeamClient,
	orgID string,
	invocationCtx workflow.InvocationContext,
	initialConfig *redteamclient.RedTeamConfig,
	in io.Reader,
	out io.Writer,
) ([]workflow.Data, error) {
	inputs := InitializeInputs()
	listModel := InitializeList()
	mainMenu := InitializeMainMenu()
	agentMenu := InitializeAgentMenu()
	agentList := InitializeAgentList()
	progressModel := progress.New(progress.WithDefaultGradient())
	spinnerModel := spinner.New()
	spinnerModel.Spinner = spinner.Dot
	spinnerModel.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	// Initialize Table
	t := table.New(
		table.WithColumns([]table.Column{
			{Title: "Severity", Width: 10},
			{Title: "Issue", Width: 30},
			{Title: "Summary", Width: 50},
		}),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	// Initialize Viewport
	vp := viewport.New(0, 0)
	vp.Style = lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		PaddingRight(2)

	m := Model{
		Step:           StepMenu, // Start with Main Menu
		Inputs:         inputs,
		List:           listModel,
		MainMenu:       mainMenu,
		AgentMenu:      agentMenu,
		AgentList:      agentList,
		ResultsTable:   t,
		DetailViewport: vp,
		Config:         redteamclient.RedTeamConfig{},
		Client:         redTeamClient,
		OrgID:          orgID,
		Ctx:            ctx,
		Progress:       progressModel,
		Spinner:        spinnerModel,
		InvocationCtx:  invocationCtx,
	}

	if initialConfig != nil {
		m.Config = *initialConfig

		// Populate inputs so if user chooses to edit, they are filled
		m.Inputs[0].SetValue(m.Config.Target.Name)
		m.Inputs[1].SetValue(m.Config.Target.Settings.URL)
		m.Inputs[2].SetValue(m.Config.Target.Context.Purpose)
		m.Inputs[3].SetValue(m.Config.Target.Settings.ResponseSelector)
		m.Inputs[4].SetValue(m.Config.Target.Settings.RequestBodyTemplate)

		// Set list selection
		for i, item := range m.List.Items() {
			val, ok := item.(targetTypeItem)
			if ok && string(val) == m.Config.Target.Type {
				m.List.Select(i)
				break
			}
		}

		// If config is provided, skip menu and go to confirmation
		m.Step = StepConfigConfirmation
	}

	// If OrgID is missing, we might want to start at StepAuthCheck
	// But we start at Welcome now, so the transition logic will handle it.

	p := tea.NewProgram(&m, tea.WithInput(in), tea.WithOutput(out))
	finalModel, err := p.Run()
	if err != nil {
		return nil, fmt.Errorf("error running TUI: %w", err)
	}

	finalM, ok := finalModel.(*Model)
	if !ok {
		return nil, fmt.Errorf("internal error: invalid model type")
	}

	if finalM.Result != nil {
		if finalM.RawResults != nil {
			resultsBytes, err := json.Marshal(finalM.RawResults)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal results: %w", err)
			}

			wd := workflow.NewData(
				workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("redteam"), "redteam"),
				"application/json",
				resultsBytes,
			)
			return []workflow.Data{wd}, nil
		}
		// Return results in workflow data format if needed, or just nil since we printed them
		// Ideally we match the output format of the non-interactive mode
		// But for now, returning nil is fine as we are handling the display.
		return nil, nil
	}

	if finalM.Err != nil {
		return nil, finalM.Err
	}

	// User quit without error
	return nil, nil
}

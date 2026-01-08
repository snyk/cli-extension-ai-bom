package tui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/snyk/go-application-framework/pkg/configuration"

	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
)

const (
	pollInterval = time.Second * 2
)

func (m *Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, m.Spinner.Tick)
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.updateKeyMsg(msg)

	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.List.SetWidth(msg.Width)
		m.Progress.Width = msg.Width - 10

		// Update Table Dimensions
		tableHeight := 15
		if msg.Height > 20 {
			tableHeight = msg.Height - 10
		}
		m.ResultsTable.SetWidth(msg.Width - 4)
		m.ResultsTable.SetHeight(tableHeight)

		availWidth := msg.Width - 10
		cols := m.ResultsTable.Columns()
		if len(cols) == 3 {
			cols[0].Width = int(float64(availWidth) * 0.15)
			cols[1].Width = int(float64(availWidth) * 0.35)
			cols[2].Width = int(float64(availWidth) * 0.50)
			m.ResultsTable.SetColumns(cols)
		}

		m.DetailViewport.Width = msg.Width - 4
		m.DetailViewport.Height = msg.Height - 6
		return m, nil

	case spinner.TickMsg:
		m.Spinner, cmd = m.Spinner.Update(msg)
		return m, cmd

	case ScanStatusMsg:
		return m.updateScanStatus(&msg)

	case PostAuthMsg:
		return m.updatePostAuthMsg(msg)

	case progress.FrameMsg:
		progressModel, progCmd := m.Progress.Update(msg)
		if pm, ok := progressModel.(progress.Model); ok {
			m.Progress = pm
		}
		return m, progCmd

	case ScanCompleteMsg:
		return m.updateScanCompleteMsg(msg)
	}

	if m.Step < StepScanning && m.Step != StepTargetType {
		idx := inputIndexForStep(m.Step)
		if idx >= 0 {
			m.Inputs[idx], cmd = m.Inputs[idx].Update(msg)
			return m, cmd
		}
	}

	return m, nil
}

func (m *Model) updatePostAuthMsg(msg PostAuthMsg) (tea.Model, tea.Cmd) {
	if msg.Err != nil {
		m.Err = msg.Err
		return m, nil
	}
	config := m.InvocationCtx.GetConfiguration()
	m.OrgID = config.GetString(configuration.ORGANIZATION)
	if m.OrgID != "" {
		m.Err = nil
		m.Step = StepTargetName
		if idx := inputIndexForStep(m.Step); idx >= 0 {
			m.Inputs[idx].Focus()
		}
		return m, textinput.Blink
	}
	m.Err = fmt.Errorf("authentication completed but Organization ID is still missing")
	return m, nil
}

func (m *Model) updateScanCompleteMsg(msg ScanCompleteMsg) (tea.Model, tea.Cmd) {
	if msg.Err != nil {
		m.Err = msg.Err
		return m, nil
	}
	m.Result = msg.Result
	m.RawResults = msg.RawResults
	m.ResultsTable.SetRows(msg.Rows)
	m.Step = StepResults
	m.ResultsTable.SetWidth(m.Width - 4)
	return m, nil
}

func (m *Model) updateKeyMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyEsc:
		// Allow back navigation or exit? For now exit.
		return m, tea.Quit
	default:
	}

	switch m.Step {
	case StepWelcome:
		return m.updateWelcomeStep(msg)
	case StepAuthCheck:
		return m.updateAuthStep(msg)
	case StepResults:
		return m.updateResultsStep(msg)
	case StepFindingDetails:
		return m.updateFindingDetailsStep(msg)
	case StepScanning:
		return m.updateScanningStep(msg)
	case StepConfigConfirmation:
		return m.updateConfigConfirmationStep(msg)
	case StepTargetType:
		return m.updateTargetTypeStep(msg)
	default:
		// Form inputs
		if m.Step < StepScanning {
			return m.updateFormInputStep(msg)
		}
	}
	return m, nil
}

func (m *Model) updateWelcomeStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type == tea.KeyEnter {
		// Determine next step
		switch {
		case m.OrgID == "":
			m.Step = StepAuthCheck
		case m.Config.Target.Name != "": // Config already loaded
			m.Step = StepConfigConfirmation
		default:
			m.Step = StepTargetName
			// Focus the first input if we skip auth check
			if idx := inputIndexForStep(m.Step); idx >= 0 {
				m.Inputs[idx].Focus()
			}
		}
		return m, textinput.Blink
	}
	if msg.String() == "q" {
		return m, tea.Quit
	}
	return m, nil
}

func (m *Model) updateAuthStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type == tea.KeyEnter {
		// Suspend TUI, run Auth, Resume
		authCmd := runAuthCmd(m)
		return m, authCmd
	}
	if msg.String() == "q" {
		return m, tea.Quit
	}
	return m, nil
}

func (m *Model) updateResultsStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.ResultsTable, cmd = m.ResultsTable.Update(msg)
	if msg.String() == "q" {
		return m, tea.Quit
	}
	if msg.Type == tea.KeyEnter {
		// Select finding
		idx := m.ResultsTable.Cursor()
		if idx >= 0 && idx < len(m.RawResults.Results) {
			m.SelectedFinding = &m.RawResults.Results[idx]
			m.Step = StepFindingDetails

			// Prepare viewport content
			content := formatFindingDetails(m.SelectedFinding)
			m.DetailViewport.SetContent(content)
			m.DetailViewport.GotoTop()
		}
	}
	return m, cmd
}

func (m *Model) updateFindingDetailsStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.DetailViewport, cmd = m.DetailViewport.Update(msg)
	if msg.String() == "q" || msg.Type == tea.KeyEsc {
		m.Step = StepResults
		m.SelectedFinding = nil
		return m, nil
	}
	return m, cmd
}

func (m *Model) updateScanningStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "q" {
		return m, tea.Quit
	}
	if msg.String() == "e" || msg.Type == tea.KeyEnter {
		// Retry / Edit config
		// Go back to the first config step
		m.Err = nil
		m.Step = StepTargetName
		// Focus first input
		if idx := inputIndexForStep(m.Step); idx >= 0 {
			m.Inputs[idx].Focus()
		}
		return m, textinput.Blink
	}
	return m, nil
}

func (m *Model) updateConfigConfirmationStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "y" || msg.Type == tea.KeyEnter {
		m.Step = StepScanning
		scanCmd := startScan(m)
		return m, scanCmd
	}
	if msg.String() == "q" || msg.String() == "n" {
		return m, tea.Quit
	}
	if msg.String() == "e" {
		m.Step = StepTargetName
		// Focus the first input
		if idx := inputIndexForStep(m.Step); idx >= 0 {
			m.Inputs[idx].Focus()
		}
		return m, textinput.Blink
	}
	return m, nil
}

func (m *Model) updateTargetTypeStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var listCmd tea.Cmd
	m.List, listCmd = m.List.Update(msg)

	// Check if enter was pressed to select
	if msg.Type == tea.KeyEnter {
		selectedItem, ok := m.List.SelectedItem().(targetTypeItem)
		if ok {
			m.Config.Target.Type = string(selectedItem)
			m.Step++

			// Focus the next input (Target URL)
			if idx := inputIndexForStep(m.Step); idx >= 0 {
				m.Inputs[idx].Focus()
			}

			return m, textinput.Blink
		}
	}
	return m, listCmd
}

func (m *Model) updateFormInputStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	idx := inputIndexForStep(m.Step)
	if idx < 0 {
		return m, nil
	}

	if msg.Type == tea.KeyEnter {
		// Validate and move to next step
		val := m.Inputs[idx].Value()
		if val == "" {
			m.Err = fmt.Errorf("this field is required")
			return m, nil
		}
		m.Err = nil

		// Save value
		saveValue(m, m.Step, val)

		// Unfocus current
		m.Inputs[idx].Blur()

		m.Step++
		if m.Step == StepScanning {
			scanCmd := startScan(m)
			return m, scanCmd
		}

		// Focus next input if applicable
		if nextIdx := inputIndexForStep(m.Step); nextIdx >= 0 {
			m.Inputs[nextIdx].Focus()
		}

		return m, textinput.Blink
	}

	var cmd tea.Cmd
	m.Inputs[idx], cmd = m.Inputs[idx].Update(msg)
	return m, cmd
}

func (m *Model) updateScanStatus(msg *ScanStatusMsg) (tea.Model, tea.Cmd) {
	if msg.Err != nil {
		m.Err = msg.Err
		m.Step = StepError
		return m, nil
	}

	if msg.ScanID != "" {
		m.ScanID = msg.ScanID
	}

	// Update state for View
	m.ScanStatus = msg.Status
	m.ScanDone = msg.Done
	m.ScanTotal = msg.Total

	cmd := m.Progress.SetPercent(msg.Progress)

	if msg.Status == redteamclient.AIScanStatusCompleted {
		// Fetch final results
		resultsCmd := fetchResults(m)
		return m, resultsCmd
	}

	if msg.Status == redteamclient.AIScanStatusFailed {
		m.Err = fmt.Errorf("scan failed: %s", msg.Status) // Fallback
		if len(msg.Feedback.Error) > 0 {
			backendError := msg.Feedback.Error[0]
			m.Err = fmt.Errorf("Scan failed: %s - %s", backendError.Code, backendError.Message)
		}
		m.Step = StepError
		return m, nil
	}

	// Continue polling
	pollCmd := pollScan(m)
	return m, tea.Batch(cmd, pollCmd)
}

func inputIndexForStep(step Step) int {
	switch step {
	case StepTargetName:
		return 0
	case StepTargetURL:
		return 1
	case StepTargetPurpose:
		return 2
	case StepResponseSelector:
		return 3
	case StepRequestBody:
		return 4
	default:
	}
	return -1
}

func saveValue(m *Model, step Step, val string) {
	switch step {
	case StepTargetName:
		m.Config.Target.Name = val
	case StepTargetURL:
		m.Config.Target.Settings.URL = val
	case StepTargetPurpose:
		m.Config.Target.Context.Purpose = val
	case StepResponseSelector:
		m.Config.Target.Settings.ResponseSelector = val
	case StepRequestBody:
		m.Config.Target.Settings.RequestBodyTemplate = val
	default:
	}
}

// Commands

func startScan(m *Model) tea.Cmd {
	return func() tea.Msg {
		// Create Scan
		scanID, err := m.Client.CreateScan(m.Ctx, m.OrgID, &m.Config)
		if err != nil {
			return ScanStatusMsg{Err: err}
		}

		m.ScanID = scanID
		return ScanStatusMsg{Status: redteamclient.AIScanStatusQueued, ScanID: scanID}
	}
}

func pollScan(m *Model) tea.Cmd {
	return tea.Tick(pollInterval, func(_ time.Time) tea.Msg {
		scan, err := m.Client.GetScan(m.Ctx, m.OrgID, m.ScanID)
		if err != nil {
			return ScanStatusMsg{Err: err}
		}

		progress := 0.0
		done := 0
		total := 0
		if scan.Feedback.Status != nil && scan.Feedback.Status.Total != nil && *scan.Feedback.Status.Total > 0 {
			done = *scan.Feedback.Status.Done
			total = *scan.Feedback.Status.Total
			progress = float64(done) / float64(total)
		}

		return ScanStatusMsg{
			Status:   scan.Status,
			Progress: progress,
			Done:     done,
			Total:    total,
			ScanID:   m.ScanID,
			Feedback: scan.Feedback,
		}
	})
}

func fetchResults(m *Model) tea.Cmd {
	return func() tea.Msg {
		results, err := m.Client.GetScanResults(m.Ctx, m.OrgID, m.ScanID)
		if err != nil {
			return ScanCompleteMsg{Err: err}
		}

		// Parse results into ScanResult
		// This is a simplification. Real implementation should aggregate results.
		res := &ScanResult{
			Summary: "Scan completed successfully.",
		}

		var rows []table.Row
		for i := range results.Results {
			v := &results.Results[i]
			// Update stats
			switch v.Severity {
			case "critical":
				res.Criticals++
			case "high":
				res.Highs++
			case "medium":
				res.Mediums++
			case "low":
				res.Lows++
			}

			// Create table row
			// Severity | Issue | Summary
			// Truncate summary if needed
			summary := v.Evidence.Content.Reason
			if len(summary) > 50 {
				summary = summary[:47] + "..."
			}
			rows = append(rows, table.Row{
				v.Severity,
				v.Definition.Name,
				summary,
			})
		}

		return ScanCompleteMsg{Result: res, RawResults: &results, Rows: rows}
	}
}

package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"gopkg.in/yaml.v3"

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
		return m.updateWindowSize(msg)

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

	case ConfigLoadedMsg:
		return m.updateConfigLoaded(msg)

	case ResultsLoadedMsg:
		return m.updateResultsLoaded(msg)

	case AgentsFetchedMsg:
		return m.updateAgentsFetched(msg)

	case AgentCreatedMsg:
		return m.updateAgentCreated(msg)

	case ResultsSavedMsg:
		if msg.Err != nil {
			m.Err = fmt.Errorf("failed to save results: %w", msg.Err)
			m.Step = StepError
			return m, nil
		}
		// Exit after saving
		return m, tea.Quit
	}

	return m.updateInputs(msg)
}

func (m *Model) updateInputs(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	idx := inputIndexForStep(m.Step)
	if idx >= 0 {
		m.Inputs[idx], cmd = m.Inputs[idx].Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) updateWindowSize(msg tea.WindowSizeMsg) (tea.Model, tea.Cmd) {
	m.Width = msg.Width
	m.Height = msg.Height
	m.List.SetWidth(msg.Width)
	m.Progress.Width = msg.Width - 10

	// Calculate header height (Title + Dog + Spacing)
	// Title: ~3 lines
	// Dog: 10 lines
	// Spacing: ~4 lines
	headerHeight := 18

	// Update Table Dimensions
	tableHeight := 15
	if msg.Height > 20 {
		tableHeight = msg.Height - headerHeight - 2
	}
	m.ResultsTable.SetWidth(msg.Width - 4)
	m.ResultsTable.SetHeight(tableHeight)

	// Update Menu Dimensions
	m.MainMenu.SetWidth(msg.Width)
	m.MainMenu.SetHeight(msg.Height - headerHeight)
	m.AgentMenu.SetWidth(msg.Width)
	m.AgentMenu.SetHeight(msg.Height - headerHeight)
	m.AgentList.SetWidth(msg.Width)
	m.AgentList.SetHeight(msg.Height - headerHeight)

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
		m.Step = StepMenu
		return m, nil
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

	return m.updateStepState(msg)
}

func (m *Model) updateStepState(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
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
	case StepMenu:
		return m.updateMenuStep(msg)
	case StepAgentMenu:
		return m.updateAgentMenuStep(msg)
	case StepAgentList:
		return m.updateAgentListStep(msg)
	case StepSaveConfirmation:
		return m.updateSaveConfirmationStep(msg)
	case StepConfigPath, StepResultsPath, StepAgentCreate, StepSavePath:
		return m.updateFormInputStep(msg)
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
			m.Step = StepMenu
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
		// Ask if they want to save results
		m.Step = StepSaveConfirmation
		return m, nil
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

func (m *Model) updateSaveConfirmationStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "y" || msg.Type == tea.KeyEnter {
		m.Step = StepSavePath
		// Focus the save path input
		if idx := inputIndexForStep(m.Step); idx >= 0 {
			m.Inputs[idx].Focus()
		}
		return m, textinput.Blink
	}
	if msg.String() == "n" || msg.String() == "q" {
		return m, tea.Quit
	}
	return m, nil
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

func (m *Model) updateMenuStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var listCmd tea.Cmd
	m.MainMenu, listCmd = m.MainMenu.Update(msg)

	if msg.Type != tea.KeyEnter {
		return m, listCmd
	}

	selectedItem, ok := m.MainMenu.SelectedItem().(menuItem)
	if !ok {
		return m, listCmd
	}

	switch selectedItem.id {
	case "new":
		if m.OrgID == "" {
			m.Step = StepAuthCheck
			return m, nil
		}
		m.Step = StepTargetName
		if idx := inputIndexForStep(m.Step); idx >= 0 {
			m.Inputs[idx].Focus()
		}
		return m, textinput.Blink
	case "existing":
		if m.OrgID == "" {
			m.Step = StepAuthCheck
			return m, nil
		}
		m.Step = StepConfigPath
		if idx := inputIndexForStep(m.Step); idx >= 0 {
			m.Inputs[idx].Focus()
		}
		return m, textinput.Blink
	case "agent":
		if m.OrgID == "" {
			m.Step = StepAuthCheck
			return m, nil
		}
		m.Step = StepAgentMenu
		return m, nil
	case "analyze":
		m.Step = StepResultsPath
		if idx := inputIndexForStep(m.Step); idx >= 0 {
			m.Inputs[idx].Focus()
		}
		return m, textinput.Blink
	}
	return m, listCmd
}

func (m *Model) updateAgentMenuStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var listCmd tea.Cmd
	m.AgentMenu, listCmd = m.AgentMenu.Update(msg)

	if msg.Type != tea.KeyEnter {
		return m, listCmd
	}

	selectedItem, ok := m.AgentMenu.SelectedItem().(menuItem)
	if !ok {
		return m, listCmd
	}

	switch selectedItem.id {
	case "list":
		m.Step = StepAgentList
		return m, fetchAgents(m)
	case "create":
		m.Step = StepAgentCreate
		if idx := inputIndexForStep(m.Step); idx >= 0 {
			m.Inputs[idx].Focus()
		}
		return m, textinput.Blink
	}
	return m, listCmd
}

func (m *Model) updateAgentListStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var listCmd tea.Cmd
	m.AgentList, listCmd = m.AgentList.Update(msg)

	// Add deletion logic here if needed (e.g. press 'd')
	// For now, allow returning to menu
	if msg.String() == "esc" || msg.String() == "q" {
		m.Step = StepAgentMenu
		return m, nil
	}
	return m, listCmd
}

func (m *Model) updateConfigLoaded(msg ConfigLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.Err != nil {
		m.Err = fmt.Errorf("failed to load config: %w", msg.Err)
		m.Step = StepError
		return m, nil
	}
	m.Config = *msg.Config
	// Populate inputs from config
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

	m.Step = StepConfigConfirmation
	return m, nil
}

func (m *Model) updateResultsLoaded(msg ResultsLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.Err != nil {
		m.Err = fmt.Errorf("failed to load results: %w", msg.Err)
		m.Step = StepError
		return m, nil
	}
	m.RawResults = msg.Results

	// Process results
	res := &ScanResult{
		Summary: "Loaded from file.",
	}
	rows := make([]table.Row, 0, len(msg.Results.Results))
	for i := range msg.Results.Results {
		v := &msg.Results.Results[i]
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
	m.Result = res
	m.ResultsTable.SetRows(rows)
	m.Step = StepResults
	return m, nil
}

func (m *Model) updateAgentsFetched(msg AgentsFetchedMsg) (tea.Model, tea.Cmd) {
	if msg.Err != nil {
		m.Err = fmt.Errorf("failed to fetch agents: %w", msg.Err)
		m.Step = StepError
		return m, nil
	}
	m.ScanningAgents = msg.Agents
	// Populate AgentList
	items := make([]list.Item, len(msg.Agents))
	for i, agent := range msg.Agents {
		status := "Offline"
		if agent.Online {
			status = "Online"
		}
		items[i] = agentItem{
			name:   agent.Name,
			id:     agent.ID,
			status: status,
		}
	}
	m.AgentList.SetItems(items)
	return m, nil
}

func (m *Model) updateAgentCreated(msg AgentCreatedMsg) (tea.Model, tea.Cmd) {
	if msg.Err != nil {
		m.Err = fmt.Errorf("failed to create agent: %w", msg.Err)
		m.Step = StepError
		return m, nil
	}
	// Show success message with token
	tokenMsg := fmt.Sprintf("Agent Created!\n\nID: %s\nToken: %s\n\nCopy this token now, it won't be shown again.",
		msg.Agent.ID, msg.Config.FarcasterAgentToken)

	m.Err = fmt.Errorf("%s", tokenMsg) // Not really an error
	m.Step = StepError
	return m, nil
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

		// Special handling for non-linear steps
		//nolint:exhaustive // Only need to handle specific steps
		switch m.Step {
		case StepConfigPath:
			m.Inputs[idx].Blur()
			return m, loadConfigCmd(val)
		case StepResultsPath:
			m.Inputs[idx].Blur()
			return m, loadResultsCmd(val)
		case StepAgentCreate:
			m.Inputs[idx].Blur()
			return m, createAgentCmd(m, val)
		case StepSavePath:
			m.Inputs[idx].Blur()
			return m, saveResultsCmd(m, val)
		}

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
	case StepConfigPath:
		return 5
	case StepResultsPath:
		return 6
	case StepAgentCreate:
		return 7
	case StepSavePath:
		return 8
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

// Messages

type ConfigLoadedMsg struct {
	Config *redteamclient.RedTeamConfig
	Err    error
}

type ResultsLoadedMsg struct {
	Results *redteamclient.GetAIVulnerabilitiesResponseData
	Err     error
}

type AgentsFetchedMsg struct {
	Agents []redteamclient.AIScanningAgent
	Err    error
}

type AgentCreatedMsg struct {
	Agent  *redteamclient.AIScanningAgent
	Config *redteamclient.GenerateAIScanningAgentConfigData
	Err    error
}

type ResultsSavedMsg struct {
	Err error
}

// Commands

func loadConfigCmd(path string) tea.Cmd {
	return func() tea.Msg {
		data, err := os.ReadFile(path)
		if err != nil {
			return ConfigLoadedMsg{Err: err}
		}
		var config redteamclient.RedTeamConfig
		if err := yaml.Unmarshal(data, &config); err != nil {
			return ConfigLoadedMsg{Err: err}
		}
		return ConfigLoadedMsg{Config: &config}
	}
}

func loadResultsCmd(path string) tea.Cmd {
	return func() tea.Msg {
		data, err := os.ReadFile(path)
		if err != nil {
			return ResultsLoadedMsg{Err: err}
		}
		var results redteamclient.GetAIVulnerabilitiesResponseData
		if err := json.Unmarshal(data, &results); err != nil {
			return ResultsLoadedMsg{Err: err}
		}
		return ResultsLoadedMsg{Results: &results}
	}
}

func fetchAgents(m *Model) tea.Cmd {
	return func() tea.Msg {
		agents, err := m.Client.ListScanningAgents(m.Ctx, m.OrgID)
		if err != nil {
			return AgentsFetchedMsg{Err: err}
		}
		return AgentsFetchedMsg{Agents: agents}
	}
}

func createAgentCmd(m *Model, name string) tea.Cmd {
	return func() tea.Msg {
		agent, err := m.Client.CreateScanningAgent(m.Ctx, m.OrgID, name)
		if err != nil {
			return AgentCreatedMsg{Err: err}
		}
		config, err := m.Client.GenerateScanningAgentConfig(m.Ctx, m.OrgID, agent.ID)
		if err != nil {
			return AgentCreatedMsg{Err: err}
		}
		return AgentCreatedMsg{Agent: agent, Config: config}
	}
}

func saveResultsCmd(m *Model, path string) tea.Cmd {
	return func() tea.Msg {
		if m.RawResults == nil {
			return ResultsSavedMsg{Err: fmt.Errorf("no results to save")}
		}
		data, err := json.MarshalIndent(m.RawResults, "", "  ")
		if err != nil {
			return ResultsSavedMsg{Err: err}
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return ResultsSavedMsg{Err: err}
		}
		return ResultsSavedMsg{}
	}
}

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

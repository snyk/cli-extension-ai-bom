package tui

import (
	"context"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/snyk/go-application-framework/pkg/workflow"

	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
)

type Step int

const (
	StepWelcome Step = iota
	StepAuthCheck
	StepConfigConfirmation
	StepTargetName
	StepTargetType
	StepTargetURL
	StepTargetPurpose
	StepResponseSelector
	StepRequestBody
	StepScanning
	StepResults
	StepFindingDetails
	StepError
	StepMenu
	StepConfigPath
	StepResultsPath
	StepAgentMenu
	StepAgentList
	StepAgentCreate
	StepSaveConfirmation
	StepSavePath
)

type ScanResult struct {
	Criticals int
	Highs     int
	Mediums   int
	Lows      int
	Summary   string
}

type Model struct {
	Step   Step
	Width  int
	Height int
	Err    error

	// Inputs
	Inputs []textinput.Model
	List   list.Model

	// Menus
	MainMenu  list.Model
	AgentMenu list.Model
	AgentList list.Model

	// Config State
	Config redteamclient.RedTeamConfig
	OrgID  string

	// Scanning State
	Client         redteamclient.RedTeamClient
	ScanningAgents []redteamclient.AIScanningAgent
	ScanID         string
	Spinner        spinner.Model
	Progress       progress.Model
	Result         *ScanResult
	RawResults     *redteamclient.GetAIVulnerabilitiesResponseData

	// Results View State
	ResultsTable    table.Model
	DetailViewport  viewport.Model
	SelectedFinding *redteamclient.AIVulnerability

	// Scan Progress State
	ScanStatus redteamclient.AIScanStatus
	ScanDone   int
	ScanTotal  int

	// Context for cancellation
	//nolint:containedctx // Context is needed for commands
	Ctx context.Context

	// Framework Context to invoke other workflows (e.g. auth)
	InvocationCtx workflow.InvocationContext
}

// TickMsg is sent to update the progress bar.
type TickMsg time.Time

// ScanStatusMsg carries updates from the poller.
type ScanStatusMsg struct {
	Status   redteamclient.AIScanStatus
	Progress float64
	Done     int
	Total    int
	ScanID   string
	Err      error
	Feedback redteamclient.AIScanFeedback
}

// ScanCompleteMsg carries the final results.
type ScanCompleteMsg struct {
	Result     *ScanResult
	RawResults *redteamclient.GetAIVulnerabilitiesResponseData
	Rows       []table.Row
	Err        error
}

package tui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// InitializeInputs sets up the text input fields.
func InitializeInputs() []textinput.Model {
	inputs := make([]textinput.Model, 8)

	// Target Name
	inputs[0] = textinput.New()
	inputs[0].Placeholder = "My Red Team Target"
	inputs[0].Focus()
	inputs[0].CharLimit = 50
	inputs[0].Width = 30
	inputs[0].Prompt = ""

	// Target URL
	inputs[1] = textinput.New()
	inputs[1].Placeholder = "https://example.com/api/chat"
	inputs[1].CharLimit = 200
	inputs[1].Width = 50
	inputs[1].Prompt = ""

	// Context / Purpose
	inputs[2] = textinput.New()
	inputs[2].Placeholder = "This is a chatbot for customer support"
	inputs[2].CharLimit = 200
	inputs[2].Width = 50
	inputs[2].Prompt = ""

	// Response Selector
	inputs[3] = textinput.New()
	inputs[3].Placeholder = "response.message"
	inputs[3].CharLimit = 100
	inputs[3].Width = 30
	inputs[3].Prompt = ""
	inputs[3].SetValue("response")

	// Request Body Template
	inputs[4] = textinput.New()
	inputs[4].Placeholder = `{"message": "{{prompt}}"}`
	inputs[4].CharLimit = 500
	inputs[4].Width = 60
	inputs[4].Prompt = ""
	inputs[4].SetValue(`{"message": "{{prompt}}"}`)

	// Config File Path (Index 5)
	inputs[5] = textinput.New()
	inputs[5].Placeholder = "/path/to/redteam.yaml"
	inputs[5].CharLimit = 200
	inputs[5].Width = 50
	inputs[5].Prompt = ""

	// Results File Path (Index 6)
	inputs[6] = textinput.New()
	inputs[6].Placeholder = "/path/to/results.json"
	inputs[6].CharLimit = 200
	inputs[6].Width = 50
	inputs[6].Prompt = ""

	// Agent Name (Index 7)
	inputs[7] = textinput.New()
	inputs[7].Placeholder = "My Scanning Agent"
	inputs[7].CharLimit = 50
	inputs[7].Width = 30
	inputs[7].Prompt = ""

	// Save Results Path (Index 8)
	inputs = append(inputs, textinput.New())
	inputs[8].Placeholder = "redteam-results.json"
	inputs[8].CharLimit = 200
	inputs[8].Width = 50
	inputs[8].Prompt = ""

	return inputs
}

// targetTypeItem implements list.Item.
type targetTypeItem string

func (i targetTypeItem) FilterValue() string { return "" }

type targetTypeDelegate struct{}

func (d targetTypeDelegate) Height() int                             { return 1 }
func (d targetTypeDelegate) Spacing() int                            { return 0 }
func (d targetTypeDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }

//nolint:gocritic // hugeParam: m is heavy - required by interface
func (d targetTypeDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(targetTypeItem)
	if !ok {
		return
	}

	str := string(i)
	fn := lipgloss.NewStyle().PaddingLeft(4).Render
	if index == m.Index() {
		fn = func(s ...string) string {
			return lipgloss.NewStyle().PaddingLeft(2).Foreground(special).SetString("> " + strings.Join(s, " ")).String()
		}
	}

	fmt.Fprint(w, fn(str))
}

// menuItem implements list.Item.
type menuItem struct {
	title string
	desc  string
	id    string
}

func (i menuItem) Title() string       { return i.title }
func (i menuItem) Description() string { return i.desc }
func (i menuItem) FilterValue() string { return i.title }

type agentItem struct {
	name   string
	id     string
	status string
}

func (i agentItem) Title() string       { return i.name }
func (i agentItem) Description() string { return fmt.Sprintf("ID: %s | Status: %s", i.id, i.status) }
func (i agentItem) FilterValue() string { return i.name }

func InitializeList() list.Model {
	items := []list.Item{
		targetTypeItem("api"),
		targetTypeItem("socket_io"),
	}

	const defaultWidth = 20
	const listHeight = 14

	l := list.New(items, targetTypeDelegate{}, defaultWidth, listHeight)
	l.Title = "Select Target Type"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.PaginationStyle = list.DefaultStyles().PaginationStyle
	l.Styles.HelpStyle = list.DefaultStyles().HelpStyle

	return l
}

func InitializeMainMenu() list.Model {
	items := []list.Item{
		menuItem{title: "Start scan with a new target", desc: "Configure a new Red Team scan interactively", id: "new"},
		menuItem{title: "Start scan with an existing target", desc: "Load configuration from a file", id: "existing"},
		menuItem{title: "Configure scanning agent", desc: "Manage Red Team scanning agents", id: "agent"},
		menuItem{title: "Analyze existing results", desc: "Load and view results from a JSON file", id: "analyze"},
	}

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Main Menu"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	return l
}

func InitializeAgentMenu() list.Model {
	items := []list.Item{
		menuItem{title: "List Scanning Agents", desc: "View all available scanning agents", id: "list"},
		menuItem{title: "Create Scanning Agent", desc: "Create a new scanning agent", id: "create"},
	}

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Scanning Agents"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	return l
}

func InitializeAgentList() list.Model {
	l := list.New([]list.Item{}, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Available Scanning Agents"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	return l
}

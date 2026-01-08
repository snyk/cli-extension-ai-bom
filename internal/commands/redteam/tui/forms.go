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
	inputs := make([]textinput.Model, 6)

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

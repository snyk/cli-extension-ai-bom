package tui

import (
	"fmt"
	"os/exec"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// PostAuthMsg indicates auth flow finished.
type PostAuthMsg struct {
	Err error
}

func runAuthCmd(m *Model) tea.Cmd {
	// We create a dummy exec.Cmd just to satisfy the API,
	// but the real work happens in the callback.
	// NOTE: tea.ExecProcess triggers the callback *after* the process runs.
	// But we want to run Go code.
	//
	// So we can use a trick: `true` command (or similar no-op)
	// and do the auth in the callback.

	c := exec.Command("true") // no-op command

	return tea.ExecProcess(c, func(err error) tea.Msg {
		if err != nil {
			return PostAuthMsg{Err: err}
		}

		// This runs after `true` finishes, with terminal restored (mostly).
		//nolint:forbidigo // Print to stdout while TUI is suspended
		fmt.Println("Starting authentication...")

		authWorkflowID := workflow.NewWorkflowIdentifier("auth")
		engine := m.InvocationCtx.GetEngine()
		if engine == nil {
			return PostAuthMsg{Err: fmt.Errorf("workflow engine not found")}
		}

		_, invokeErr := engine.Invoke(authWorkflowID)
		return PostAuthMsg{Err: invokeErr}
	})
}

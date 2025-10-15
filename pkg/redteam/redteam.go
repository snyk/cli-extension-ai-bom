package redteam

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/redteam"
)

func Init(e workflow.Engine) error {
	if err := redteam.RegisterWorkflows(e); err != nil {
		return fmt.Errorf("error registering redteam workflow: %w", err)
	}
	return nil
}

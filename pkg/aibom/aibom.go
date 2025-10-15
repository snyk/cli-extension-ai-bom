package aibom

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/aibomcreate"
)

func Init(e workflow.Engine) error {
	if err := aibomcreate.RegisterWorkflows(e); err != nil {
		return fmt.Errorf("error registering aibomcreate workflow: %w", err)
	}
	return nil
}

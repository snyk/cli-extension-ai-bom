package redteam

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/cli-extension-ai-bom/internal/utils"
)

var WorkflowID = workflow.NewWorkflowIdentifier("redteam")

func RegisterWorkflows(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-ai-bom-redteam", pflag.ExitOnError)
	flagset.Bool(utils.FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")

	configuration := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(WorkflowID, configuration, Workflow); err != nil {
		return fmt.Errorf("error while registering redteam workflow: %w", err)
	}
	return nil
}

func Workflow(_ workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	workflowData := workflow.NewData(workflow.NewTypeIdentifier(WorkflowID, "redteam"), "application/text", "Red team workflow executed successfully")
	return []workflow.Data{workflowData}, nil
}

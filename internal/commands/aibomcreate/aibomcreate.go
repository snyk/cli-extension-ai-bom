package aibomcreate

import (
	"errors"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-ai-bom/internal/services/code"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"

	"github.com/spf13/pflag"
)

var WorkflowID = workflow.NewWorkflowIdentifier("aibom")

func RegisterWorkflows(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-ai-bom", pflag.ExitOnError)
	flagset.Bool(utils.FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")

	configuration := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(WorkflowID, configuration, AiBomWorkflow); err != nil {
		return fmt.Errorf("error while registering AI-BOM workflow: %w", err)
	}
	return nil
}

func AiBomWorkflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	codeService := code.NewCodeServiceImpl()
	return RunAiBomWorkflow(invocationCtx, codeService)
}

func RunAiBomWorkflow(invocationCtx workflow.InvocationContext, codeService code.CodeService) (output []workflow.Data, err error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()

	config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
	experimental := config.GetBool(utils.FlagExperimental)
	path := config.GetString(configuration.INPUT_DIRECTORY)

	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		//nolint:stylecheck,revive // The string begins with a capital in order to remain consistent with other Snyk commands
		return nil, fmt.Errorf("Flag `--experimental` is required to execute this command.")
	}

	logger.Debug().Msg("AI BOM workflow start")

	response, resultMetaData, err := codeService.Analyze(path, invocationCtx.GetNetworkAccess().GetHttpClient, logger, config, invocationCtx.GetUserInterface())
	if err != nil {
		return nil, fmt.Errorf("code client failed to analyze bundle: %w", err)
	}
	logger.Debug().Msgf("Result metadata: %+v", resultMetaData)

	aiBomDoc, err := extractSbomFromResult(response, logger)
	if err != nil {
		return nil, err
	}

	logger.Debug().Msg("Successfully generated AI BOM document.")
	return aiBomDoc, nil
}

func extractSbomFromResult(response *code.AnalysisResponse, logger *zerolog.Logger) (output []workflow.Data, err error) {
	if len(response.Sarif.Runs) != 1 {
		logger.Debug().Msgf("Failed to extract AI-BOM from SARIF result, %d runs in SARIF, expected 1", len(response.Sarif.Runs))
		return nil, errors.New("failed to extract AI-BOM from SARIF result")
	}
	if len(response.Sarif.Runs[0].Results) != 1 {
		logger.Debug().Msgf("Failed to extract SBOM from SARIF result, %d results in Runs[0], expected 1", len(response.Sarif.Runs[0].Results))
		return nil, errors.New("failed to extract SBOM from SARIF result")
	}
	return []workflow.Data{newWorkflowData("application/json", []byte(response.Sarif.Runs[0].Results[0].Message.Text))}, nil
}

//nolint:ireturn // Unable to change return type of external library
func newWorkflowData(contentType string, aisbom []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowID, "aibom"),
		contentType,
		aisbom,
	)
}

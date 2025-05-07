package aibomcreate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

	if !config.GetBool(utils.FlagSkipDepGraph) {
		var depGraphResult *DepGraphResult
		depGraphResult, err = GetDepGraph(invocationCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to get the depgraph: %w", err)
		}
		numGraphs := len(depGraphResult.DepGraphBytes)
		logger.Debug().Msgf("Generated %d depgraph(s)\n", numGraphs)

		_, err = writeRawMessagesToFiles(depGraphResult.DepGraphBytes, path+"/depgraphs", "deps")
		if err != nil {
			return nil, fmt.Errorf("writing depgraphs to files failed: %w", err)
		}
	}

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

func writeRawMessagesToFiles(data []json.RawMessage, outputDir, filenamePrefix string) ([]string, error) {
	// Create the output directory if it doesn't exist
	err := os.MkdirAll(outputDir, 0o0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	filePaths := make([]string, len(data))

	for i, rawMessage := range data {
		filename := filepath.Join(outputDir, fmt.Sprintf("%s_%d.snykdepgraph", filenamePrefix, i))

		// Write the json.RawMessage to the file
		err := os.WriteFile(filename, rawMessage, 0o0600)
		if err != nil {
			return nil, fmt.Errorf("failed to write to file %s: %w", filename, err)
		}

		filePaths[i] = filename
	}

	return filePaths, nil
}

//nolint:ireturn // Unable to change return type of external library
func newWorkflowData(contentType string, aisbom []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowID, "aibom"),
		contentType,
		aisbom,
	)
}
